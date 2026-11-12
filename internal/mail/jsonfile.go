package mail

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// loadJSONFile 读取 JSON 文件到 dst；文件不存在视为空数据。
func loadJSONFile(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(dst)
}

// saveJSONFile 原子写入 JSON 文件：先写临时文件再 rename，避免进程中断留下半截文件。
func saveJSONFile(path string, src any) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(src); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("写入 %s 失败: %w", path, err)
	}
	return nil
}
