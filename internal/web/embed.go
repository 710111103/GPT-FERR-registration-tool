// Package web 把前端静态资源编译进二进制。
//
// 这样最终产物是一个单文件可执行程序：拷到任意 Windows/Linux 机器上
// 直接运行即可，不需要额外的 templates 目录。
package web

import "embed"

// Static 内嵌前端资源。目录结构：web/static/index.html
//
//go:embed static/*
var Static embed.FS
