package api

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func timeNow() time.Time { return time.Now() }

// writeEnv 把键值合并进项目根目录的 .env。
// 语义与 webui/config_editor.update_config 一致：只改给定键，保留其余行与注释。
func writeEnv(root string, updates map[string]string) error {
	if len(updates) == 0 {
		return nil
	}
	path := filepath.Join(root, ".env")

	// 读取现有内容
	type kv struct{ k, v string }
	var order []string
	existing := map[string]string{}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				order = append(order, line)
				continue
			}
			k, v, ok := strings.Cut(trimmed, "=")
			if !ok {
				order = append(order, line)
				continue
			}
			k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
			existing[k] = v
			order = append(order, "\x00"+k) // 占位，稍后按新值重写
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return err
		}
	}

	// 应用更新
	newKeys := make([]string, 0)
	for k, v := range updates {
		if _, ok := existing[k]; !ok {
			newKeys = append(newKeys, k)
		}
		existing[k] = v
	}
	sort.Strings(newKeys)

	// 重建文件
	var sb strings.Builder
	for _, line := range order {
		if strings.HasPrefix(line, "\x00") {
			k := strings.TrimPrefix(line, "\x00")
			sb.WriteString(envLine(k, existing[k]))
			sb.WriteString("\n")
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	for _, k := range newKeys {
		sb.WriteString(envLine(k, existing[k]))
		sb.WriteString("\n")
	}

	// 原子写入
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("替换 .env 失败: %w", err)
	}
	return nil
}

// envLine 生成一行 KEY=value，值含空格或 # 时加引号。
func envLine(k, v string) string {
	if strings.ContainsAny(v, " #\"'") {
		return fmt.Sprintf("%s=%q", k, v)
	}
	return k + "=" + v
}
