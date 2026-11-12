package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
	"golang.org/x/net/proxy"
)

// Relay 是一个本地 HTTP CONNECT 代理中继服务。
//
// 核心作用：
//  1. 串联代理链：把上游代理（如本机翻墙客户端）串联到目标代理（如海外住宅代理），最终到达 OpenAI。
//  2. 隧道级流量统计：精确计量整个代理会话实际跑了多少字节（上传/下载），写回任务事实。
//  3. 统一代理协议：对外统一暴露为标准 HTTP CONNECT 代理，任何工具（浏览器、CDP、tls-client）均可直接接入。
type Relay struct {
	listener      net.Listener
	targetURL     *url.URL
	upstreamURL   *url.URL
	timeout       time.Duration
	port          int
	closed        chan struct{}
	closeOnce     sync.Once
	uploadBytes   int64
	downloadBytes int64
	requestCount  int64

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
}

// NewRelay 创建并启动一个本地代理链中继服务。
// target 为出口代理（如住宅代理），upstream 可选（如本地代理 127.0.0.1:7890）。
func NewRelay(target string, upstream string, timeout time.Duration) (*Relay, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	targetNorm := config.NormalizeProxyURL(target)
	if targetNorm == "" {
		return nil, fmt.Errorf("目标代理地址为空")
	}
	tURL, err := url.Parse(targetNorm)
	if err != nil {
		return nil, fmt.Errorf("解析目标代理失败: %w", err)
	}

	var uURL *url.URL
	if upstream != "" {
		upNorm := config.NormalizeProxyURL(upstream)
		uURL, err = url.Parse(upNorm)
		if err != nil {
			return nil, fmt.Errorf("解析上游代理失败: %w", err)
		}
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("监听本地中继端口失败: %w", err)
	}

	r := &Relay{
		listener:    l,
		targetURL:   tURL,
		upstreamURL: uURL,
		timeout:     timeout,
		port:        l.Addr().(*net.TCPAddr).Port,
		closed:      make(chan struct{}),
		conns:       make(map[net.Conn]struct{}),
	}

	go r.serve()
	return r, nil
}

// ProxyURL 返回中继服务器地址，如 http://127.0.0.1:54321
func (r *Relay) ProxyURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", r.port)
}

// Traffic 返回当前累计传输的流量统计。
func (r *Relay) Traffic() domain.Traffic {
	up := atomic.LoadInt64(&r.uploadBytes)
	down := atomic.LoadInt64(&r.downloadBytes)
	reqs := atomic.LoadInt64(&r.requestCount)
	return domain.Traffic{
		UploadBytes:   up,
		DownloadBytes: down,
		TotalBytes:    up + down,
		RequestCount:  reqs,
	}
}

// Close 关闭监听器并断开全部存活连接。
func (r *Relay) Close() error {
	var err error
	r.closeOnce.Do(func() {
		close(r.closed)
		err = r.listener.Close()
		r.connsMu.Lock()
		for c := range r.conns {
			_ = c.Close()
		}
		r.connsMu.Unlock()
	})
	return err
}

func (r *Relay) trackConn(c net.Conn) {
	r.connsMu.Lock()
	r.conns[c] = struct{}{}
	r.connsMu.Unlock()
}

func (r *Relay) untrackConn(c net.Conn) {
	r.connsMu.Lock()
	delete(r.conns, c)
	r.connsMu.Unlock()
}

func (r *Relay) serve() {
	for {
		client, err := r.listener.Accept()
		if err != nil {
			select {
			case <-r.closed:
				return
			default:
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
		r.trackConn(client)
		go func(c net.Conn) {
			defer r.untrackConn(c)
			defer c.Close()
			r.handleClient(c)
		}(client)
	}
}

func (r *Relay) handleClient(client net.Conn) {
	atomic.AddInt64(&r.requestCount, 1)
	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		r.handleConnect(client, req)
	} else {
		r.handlePlainHTTP(client, req)
	}
}

func (r *Relay) handleConnect(client net.Conn, req *http.Request) {
	targetDest := req.Host
	if !strings.Contains(targetDest, ":") {
		targetDest += ":443"
	}

	remote, err := r.dialThroughChain(targetDest)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	r.bidirectionalPipe(client, remote)
}

func (r *Relay) handlePlainHTTP(client net.Conn, req *http.Request) {
	targetDest := req.URL.Host
	if targetDest == "" {
		targetDest = req.Host
	}
	if !strings.Contains(targetDest, ":") {
		targetDest += ":80"
	}

	remote, err := r.dialThroughChain(targetDest)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	if err := req.Write(remote); err != nil {
		return
	}
	r.bidirectionalPipe(client, remote)
}

// dialThroughChain 按 [本地] -> (上游代理) -> 目标代理 -> 最终目标 建立连接。
func (r *Relay) dialThroughChain(targetDest string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	// 1. 如果有上游代理（如本地 SOCKS5 翻墙代理），先通过上游连向目标代理
	baseDialer := &net.Dialer{Timeout: r.timeout}
	var dialer proxy.ContextDialer = baseDialer
	if r.upstreamURL != nil {
		upDialer, err := buildDialer(r.upstreamURL, baseDialer)
		if err != nil {
			return nil, fmt.Errorf("构建上游代理连接器失败: %w", err)
		}
		dialer = upDialer
	}

	// 2. 连接到目标代理
	targetConn, err := dialer.DialContext(ctx, "tcp", r.targetURL.Host)
	if err != nil {
		return nil, fmt.Errorf("连接目标代理 %s 失败: %w", r.targetURL.Host, err)
	}

	// 3. 根据目标代理协议握手到 targetDest
	switch strings.ToLower(r.targetURL.Scheme) {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if r.targetURL.User != nil {
			pass, _ := r.targetURL.User.Password()
			auth = &proxy.Auth{User: r.targetURL.User.Username(), Password: pass}
		}
		s5, err := proxy.SOCKS5("tcp", r.targetURL.Host, auth, &directConnDialer{conn: targetConn})
		if err != nil {
			targetConn.Close()
			return nil, err
		}
		return s5.Dial("tcp", targetDest)

	case "http", "https", "":
		// 发送 HTTP CONNECT 到目标代理
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetDest, targetDest)
		if r.targetURL.User != nil {
			user := r.targetURL.User.Username()
			pass, _ := r.targetURL.User.Password()
			authVal := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", authVal)
		}
		connectReq += "\r\n"

		if _, err := targetConn.Write([]byte(connectReq)); err != nil {
			targetConn.Close()
			return nil, fmt.Errorf("向目标代理发送 CONNECT 失败: %w", err)
		}

		resp, err := http.ReadResponse(bufio.NewReader(targetConn), nil)
		if err != nil {
			targetConn.Close()
			return nil, fmt.Errorf("读取目标代理 CONNECT 回执失败: %w", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			targetConn.Close()
			return nil, fmt.Errorf("目标代理拒绝 CONNECT: HTTP %d", resp.StatusCode)
		}
		return targetConn, nil

	default:
		targetConn.Close()
		return nil, fmt.Errorf("不支持的代理协议: %s", r.targetURL.Scheme)
	}
}

func (r *Relay) bidirectionalPipe(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> remote (upload)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, err := client.Read(buf)
			if nr > 0 {
				nw, ew := remote.Write(buf[:nr])
				if nw > 0 {
					atomic.AddInt64(&r.uploadBytes, int64(nw))
				}
				if ew != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = remote.Close()
	}()

	// remote -> client (download)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, err := remote.Read(buf)
			if nr > 0 {
				nw, ew := client.Write(buf[:nr])
				if nw > 0 {
					atomic.AddInt64(&r.downloadBytes, int64(nw))
				}
				if ew != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = client.Close()
	}()

	wg.Wait()
}

func buildDialer(u *url.URL, forward proxy.Dialer) (proxy.ContextDialer, error) {
	var auth *proxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pass}
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		d, err := proxy.SOCKS5("tcp", u.Host, auth, forward)
		if err != nil {
			return nil, err
		}
		if cd, ok := d.(proxy.ContextDialer); ok {
			return cd, nil
		}
		return &contextDialerWrapper{d}, nil
	default:
		return nil, fmt.Errorf("上游代理仅支持 socks5://，暂不支持 %s", u.Scheme)
	}
}

type directConnDialer struct {
	conn net.Conn
}

func (d *directConnDialer) Dial(network, addr string) (net.Conn, error) {
	c := d.conn
	d.conn = nil
	if c == nil {
		return nil, fmt.Errorf("连接已被消费")
	}
	return c, nil
}

type contextDialerWrapper struct {
	d proxy.Dialer
}

func (w *contextDialerWrapper) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return w.d.Dial(network, addr)
}
