package config

import (
	"strings"
	"testing"
)

func TestNormalizeProxyURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "带外层引号和转义斜杠",
			in:   `\"us.1024proxy.io:3000:user:pass\"`,
			want: "http://user:pass@us.1024proxy.io:3000",
		},
		{
			name: "常规双引号包裹",
			in:   `"1.2.3.4:8080:u:p"`,
			want: "http://u:p@1.2.3.4:8080",
		},
		{
			name: "完整 http scheme 保留",
			in:   "http://user:pass@host.com:8080",
			want: "http://user:pass@host.com:8080",
		},
		{
			name: "完整 socks5 scheme 保留",
			in:   "socks5://user:pass@127.0.0.1:1080",
			want: "socks5://user:pass@127.0.0.1:1080",
		},
		{
			name: "只有 host:port",
			in:   "127.0.0.1:7890",
			want: "http://127.0.0.1:7890",
		},
		{
			name: "空字符串",
			in:   "   ",
			want: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NormalizeProxyURL(c.in)
			if got != c.want {
				t.Errorf("NormalizeProxyURL(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}

	t.Run("1024proxy 动态 sid 自动轮换测试", func(t *testing.T) {
		in := "us.1024proxy.io:3000:tnjo72716-region-DE-sid-LkkgZWwK-t-1:spyhgr75"
		got := NormalizeProxyURL(in)
		if !strings.HasPrefix(got, "http://tnjo72716-region-DE-sid-") || !strings.HasSuffix(got, "@us.1024proxy.io:3000") {
			t.Errorf("期望生成有效代理地址，实际得到: %s", got)
		}
	})

	t.Run("sticky 规范化不轮换已有 sid", func(t *testing.T) {
		in := "http://tnjo72716-region-DE-sid-LkkgZWwK-t-1:spyhgr75@us.1024proxy.io:3000"
		if got := NormalizeProxyURLStable(in); got != in {
			t.Errorf("NormalizeProxyURLStable() = %q, want unchanged %q", got, in)
		}
	})
}
