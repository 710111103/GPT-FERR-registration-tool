// Package domain 定义跨层共享的领域类型。
//
// 设计要点：Stage 复刻 Python 版 core/registration_stage.py 的 RegistrationStage，
// 只保存"事实布尔值"，绝不保存验证码、密码、token 或 TOTP 原文。
package domain

import (
	"time"
)

// Stage 记录一次注册流程走到哪一步。与 Python 版字段一一对应，便于日志与看板对齐。
type Stage struct {
	AccountCreated     bool   `json:"account_created"`
	PasswordSet        bool   `json:"password_set"`
	OTPSent            bool   `json:"otp_sent"`
	OTPVerified        bool   `json:"otp_verified"`
	CredentialAcquired bool   `json:"credential_acquired"`
	ExistingAccount    bool   `json:"existing_account"`
	Flow               string `json:"flow"`
	FailureStage       string `json:"failure_stage,omitempty"`
	ErrorCode          string `json:"error_code,omitempty"`
}

// NewStage 返回一个未知流程的初始阶段。
func NewStage() Stage {
	return Stage{Flow: "unknown"}
}

// Fail 标记失败发生的阶段与错误码。
func (s *Stage) Fail(stage, code string) {
	if stage == "" {
		stage = "unknown"
	}
	if code == "" {
		code = "unknown"
	}
	s.FailureStage = stage
	s.ErrorCode = code
}

// EmailSource 邮箱来源标识。
type EmailSource string

const (
	SourceOutlook          EmailSource = "outlook"
	SourceGenericAPI       EmailSource = "generic_api"
	SourceIMAP             EmailSource = "imap"
	SourceCloudflare       EmailSource = "cloudflare"
	SourceCloudflareDomain EmailSource = "cloudflare_domain"
	SourceGPTMail          EmailSource = "gptmail"
	SourceMailNest         EmailSource = "mailnest"
	SourceCloudMail        EmailSource = "cloudmail"
	SourceRemail           EmailSource = "remail"
	SourceMailCode         EmailSource = "mailcode"
	SourceMailTM           EmailSource = "mailtm"
	SourceTempMailIO       EmailSource = "tempmailio"
)

// Mailbox 是一次邮箱领取的结果。Provider 负责在 Release 时回收。
type Mailbox struct {
	Email  string      `json:"email"`
	Source EmailSource `json:"source"`
	// Credential 是取码所需的上下文（refreshToken、JWT、订单 token 等），
	// 只在本进程内流转，不写入日志。
	Credential map[string]string `json:"-"`
	AcquiredAt time.Time         `json:"acquired_at"`
}

// OTPResult 是一次取码结果。
type OTPResult struct {
	Code     string
	Received time.Time
	Source   string // graph / imap / api ...
}

// JobStatus 任务状态机，取值与 Python 版保持一致以免前端改动。
type JobStatus string

const (
	JobPending   JobStatus = "pending"
	JobRunning   JobStatus = "running"
	JobStopping  JobStatus = "stopping"
	JobStopped   JobStatus = "stopped"
	JobSuccess   JobStatus = "success"
	JobFailed    JobStatus = "failed"
	JobCancelled JobStatus = "cancelled"
)

// Account 一个已注册账号。
type Account struct {
	ID        int64          `json:"id"`
	Email     string         `json:"email"`
	Status    string         `json:"status"`
	Archived  bool           `json:"archived"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	Payload   map[string]any `json:"payload,omitempty"`
}

// Job 一条注册任务记录。
type Job struct {
	ID             int64          `json:"id"`
	Email          string         `json:"email"`
	EmailSource    string         `json:"email_source"`
	BatchID        string         `json:"batch_id,omitempty"`
	Status         JobStatus      `json:"status"`
	Error          string         `json:"error,omitempty"`
	LogFile        string         `json:"log_file,omitempty"`
	AccountID      *int64         `json:"account_id,omitempty"`
	Stage          *Stage         `json:"stage,omitempty"`
	NetworkTraffic any            `json:"network_traffic,omitempty"`
	Payload        map[string]any `json:"payload,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
}

// Traffic 是 TLS 客户端在连接层观测到的流量汇总，包含 TLS、HTTP 与
// 代理帧开销，但不包含邮箱 API、控制通道及代理服务商侧的其他流量。
type Traffic struct {
	Available       bool   `json:"available"`
	Source          string `json:"source,omitempty"`
	UploadBytes     int64  `json:"upload_bytes"`
	DownloadBytes   int64  `json:"download_bytes"`
	TotalBytes      int64  `json:"total_bytes"`
	RequestCount    int64  `json:"request_count"`
	FailedCount     int64  `json:"failed_count"`
	UnfinishedCount int64  `json:"unfinished_count"`
	WSUpBytes       int64  `json:"ws_upload_bytes"`
	WSDownBytes     int64  `json:"ws_download_bytes"`
}
