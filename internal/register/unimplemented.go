package register

import (
	"context"
	"fmt"

	"github.com/turb/gpt-register/internal/domain"
)

// Unimplemented 为尚未移植的驱动提供统一占位实现。
//
// 这样做的目的：注册表可以一次性登记全部七个驱动名，
// WebUI 里能正常展示、用户能选中，真正的失败信息也明确
// （"该驱动尚未移植"），而不是"未知驱动"这种误导性错误。
type Unimplemented struct {
	DriverName string
	Hint       string
}

// Name 返回驱动名。
func (u *Unimplemented) Name() string { return u.DriverName }

// Register 永远返回未实现错误。
func (u *Unimplemented) Register(ctx context.Context, req Request) (Result, error) {
	hint := u.Hint
	if hint == "" {
		hint = "请参考 GPT-FERR-Go架构方案.md 的 Phase 2，或暂时改用 REGISTRATION_DRIVER=protocol"
	}
	s := domain.NewStage()
	s.Fail(u.DriverName, "not_implemented")
	return Result{Email: req.Email, Stage: s},
		fmt.Errorf("注册驱动 %q 在 Go 版中尚未移植。%s", u.DriverName, hint)
}
