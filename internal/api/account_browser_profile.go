package api

import (
	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/register/protocol"
)

// accountBrowserProfile 恢复账号注册时的浏览器身份。
// 旧账号仅在字段缺失时按当前配置和本次代理地区补全；已有字段不会被覆盖。
func accountBrowserProfile(acc *domain.Account, proxy string) protocol.BrowserProfile {
	if acc == nil {
		return protocol.BrowserProfile{}.Complete(proxy)
	}
	return protocol.BrowserProfileFromPayload(acc.Payload).Complete(proxy)
}

// accountSessionOptions 确保账号后续所有协议请求复用同一套
// TLS、UA、Client Hints、语言、时区、屏幕和 oai-did。
func accountSessionOptions(acc *domain.Account, proxy string) protocol.SessionOptions {
	image := accountBrowserProfile(acc, proxy)
	return protocol.SessionOptions{
		UserAgent:   image.UserAgent,
		Language:    image.Language,
		Timezone:    image.Timezone,
		Screen:      image.Screen,
		DeviceID:    accountDeviceID(acc),
		Proxy:       proxy,
		ProfileName: image.TLSProfile,
	}
}

func storeAccountBrowserProfile(acc *domain.Account, image protocol.BrowserProfile) {
	if acc == nil {
		return
	}
	if acc.Payload == nil {
		acc.Payload = map[string]any{}
	}
	image.StoreTo(acc.Payload)
}
