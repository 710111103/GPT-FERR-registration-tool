package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestLocalRelayLoopback(t *testing.T) {
	// 启动一个测试用目标服务器
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	targetPort := targetListener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				req, err := http.ReadRequest(r)
				if err != nil {
					return
				}
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"
				_, _ = c.Write([]byte(resp))
				_ = req
			}(conn)
		}
	}()

	// 启动本地中继代理（无上游，直接连向目标）
	relay, err := NewRelay(fmt.Sprintf("http://127.0.0.1:%d", targetPort), "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	if relay.port <= 0 {
		t.Errorf("中继端口非法: %d", relay.port)
	}
}
