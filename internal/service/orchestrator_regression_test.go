package service

import (
	"fmt"
	"testing"

	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/register"
	"github.com/turb/gpt-register/internal/register/protocol"
)

func TestRegistrationCanBePersistedRejectsOTPRejection(t *testing.T) {
	// 即使阶段布尔值被错误地标成成功，验证码拒绝也必须禁止密码恢复和入库。
	res := register.Result{
		Email:    "otp-rejected@example.com",
		Password: "temporary-password",
		Stage: domain.Stage{
			OTPVerified:    true,
			AccountCreated: true,
			PasswordSet:    true,
		},
	}
	err := fmt.Errorf("校验验证码失败: %w", &protocol.OTPRejectedError{Code: "wrong_email_otp_code"})
	if !isOTPRejected(err) {
		t.Fatal("包装后的 OTPRejectedError 未被识别")
	}
	if registrationCanBePersisted(res, err) {
		t.Fatal("验证码被拒绝时不得保存账号或执行密码恢复")
	}
}

func TestRegistrationCanBePersistedRequiresVerifiedStage(t *testing.T) {
	res := register.Result{
		Email:    "unverified@example.com",
		Password: "temporary-password",
		Stage: domain.Stage{
			AccountCreated: true,
			PasswordSet:    true,
		},
	}
	if registrationCanBePersisted(res, fmt.Errorf("验证码未核验")) {
		t.Fatal("未核验验证码的暂存密码不得入库")
	}
}

func TestRegistrationCanBePersistedAfterVerifiedAccount(t *testing.T) {
	res := register.Result{
		Email:    "verified@example.com",
		Password: "saved-password",
		Stage: domain.Stage{
			OTPVerified:    true,
			AccountCreated: true,
			PasswordSet:    true,
		},
	}
	if !registrationCanBePersisted(res, fmt.Errorf("会话 token 暂时读取失败")) {
		t.Fatal("验证码已核验且已建号时应允许密码保全")
	}
}
