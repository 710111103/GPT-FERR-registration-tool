package sms

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNoNumbers = errors.New("接码平台暂无可用号码（NO_NUMBERS）")
	ErrNoBalance = errors.New("接码平台余额不足（NO_BALANCE），请充值")
	ErrTimeout   = errors.New("等待短信验证码超时")
)

// Provider 是短信接码服务抽象。
type Provider interface {
	Name() string
	AcquireNumber(ctx context.Context, service, country string) (activationID string, phone string, err error)
	WaitSMSCode(ctx context.Context, activationID string, timeout, pollInterval time.Duration) (string, error)
	Cancel(ctx context.Context, activationID string) error
	Complete(ctx context.Context, activationID string) error
}
