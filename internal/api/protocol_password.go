package api

// 纯协议密码链路：对齐上游 core/password_setup_service.py 的
// _verify_password_via_liveness(protocol_only=True) 与 openai_auth.generate_registration_password。
//
// 与 refreshAccountToken 的区别是硬性的：refreshAccountToken 会先走
// session_token 极速通道，验不出「密码本身对不对」。补设密码 / 候选密码验收
// 必须只认密码 + TOTP，所以这条链路单独一份，不走会话快捷方式。

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/register/protocol"
)

// protocolDriver 取出已注册的协议驱动；缺失时返回可读错误。
func (s *Server) protocolDriver() (*protocol.Driver, error) {
	drv, ok := s.drivers.Lookup("protocol")
	if !ok {
		return nil, fmt.Errorf("未注册协议驱动")
	}
	pd, ok := drv.(*protocol.Driver)
	if !ok {
		return nil, fmt.Errorf("驱动类型不支持协议登录")
	}
	return pd, nil
}

// verifyPasswordViaProtocol 用「邮箱 + 密码 + TOTP」建立全新登录鉴权，
// 成功后独立探活 AT 并写回账号。返回新 AT。
//
// 该函数不读 session_token、不读已有 AT，命中的唯一凭据是传入的 password。
// 对齐上游 _verify_password_via_liveness 的 protocol_only 分支返回结构。
func (s *Server) verifyPasswordViaProtocol(ctx context.Context, acc *domain.Account, password string) (string, error) {
	if acc == nil || acc.Payload == nil {
		return "", fmt.Errorf("账号不存在或数据为空")
	}
	pw := strings.TrimSpace(password)
	if pw == "" {
		return "", fmt.Errorf("候选密码为空")
	}
	email := acc.Email
	dev := accountDeviceID(acc)
	totp := extractAccountSecret(acc, "totp_secret")
	proxy := s.getProxyForAccount(acc)
	image := accountBrowserProfile(acc, proxy)

	pd, err := s.protocolDriver()
	if err != nil {
		return "", err
	}

	s.appendLiveLog(email, fmt.Sprintf("[密码验收] 账号 #%d 走纯协议密码登录（不走 session_token 快捷通道）", acc.ID))
	at, newST, err := pd.LoginWithPasswordUsingProfileLogged(ctx, email, pw, totp, dev, proxy, image, func(line string) {
		s.appendLiveLog(email, line)
	})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(at) == "" {
		return "", fmt.Errorf("登录成功但未取到 Access Token")
	}

	// 独立探活：换出来的 AT 必须能被 /backend-api/wham/usage 认可。
	probeStatus, probeUID, probeCode, probeErr := s.probeAccessTokenDetailed(ctx, acc, at)
	if probeErr != nil || probeStatus != 200 {
		s.appendLiveLog(email, fmt.Sprintf("[密码验收] AT 探活未通过 (HTTP %d, code=%s, %v)", probeStatus, probeCode, probeErr))
		return "", fmt.Errorf("登录验收失败：AT 探活 HTTP %d", probeStatus)
	}

	acc.Payload["access_token"] = at
	if newST != "" {
		acc.Payload["session_token"] = newST
	}
	acc.Payload["device_id"] = dev
	if probeUID != "" {
		acc.Payload["user_id"] = probeUID
	}
	acc.Payload["token_expired"] = false
	acc.Payload["token_need_refresh"] = false
	acc.Payload["last_refreshed_at"] = time.Now().Format("2006-01-02 15:04:05")
	storeAccountBrowserProfile(acc, image)
	if _, ierr := s.store.InsertAccount(ctx, *acc); ierr != nil {
		s.appendLiveLog(email, fmt.Sprintf("[密码验收] 验收成功但入库失败: %v", ierr))
	}
	s.appendLiveLog(email, fmt.Sprintf("[密码验收] 账号 #%d 密码 + TOTP 登录验收通过 (user_id=%s)", acc.ID, probeUID))
	return at, nil
}

// -----------------------------------------------------------------------------
// 强密码生成：对齐上游 core/openai_auth.generate_registration_password
// 四组各取一个，剩余位从全字符集补齐，最后整体洗牌，长度 16。
// -----------------------------------------------------------------------------

const registrationPasswordLength = 16

func randIndex(n int) int {
	if n <= 0 {
		return 0
	}
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0
	}
	return (int(buf[0])<<8 + int(buf[1])) % n
}

// generateRegistrationPassword 返回 16 位含大小写、数字、符号的强密码。
func generateRegistrationPassword() string {
	groups := []string{
		"ABCDEFGHJKLMNPQRSTUVWXYZ",
		"abcdefghjkmnpqrstuvwxyz",
		"23456789",
		"!@#$%^&*?_-+=",
	}
	all := strings.Join(groups, "")
	chars := make([]byte, 0, registrationPasswordLength)
	for _, g := range groups {
		chars = append(chars, g[randIndex(len(g))%len(g)])
	}
	for len(chars) < registrationPasswordLength {
		chars = append(chars, all[randIndex(len(all))%len(all)])
	}
	for i := len(chars) - 1; i > 0; i-- {
		j := randIndex(i+1) % (i + 1)
		chars[i], chars[j] = chars[j], chars[i]
	}
	return string(chars)
}
