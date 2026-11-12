package protocol

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionTrafficIncludesFailedHTTPRequests(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream unavailable"))
	}))
	defer srv.Close()

	sess, err := NewSession(SessionOptions{
		UserAgent:          "traffic-test",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer sess.Close()

	resp, err := sess.Request(http.MethodGet, srv.URL, "", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}

	traffic := sess.Traffic()
	if !traffic.Available || traffic.Source != "protocol_tls" {
		t.Fatalf("traffic metadata = available:%v source:%q", traffic.Available, traffic.Source)
	}
	if traffic.RequestCount != 1 || traffic.FailedCount != 1 {
		t.Fatalf("traffic request counters = request:%d failed:%d", traffic.RequestCount, traffic.FailedCount)
	}
	if traffic.TotalBytes <= 0 {
		t.Fatalf("traffic total = %d, want > 0", traffic.TotalBytes)
	}
	if traffic.TotalBytes != traffic.UploadBytes+traffic.DownloadBytes {
		t.Fatalf("traffic total = %d, upload+download = %d", traffic.TotalBytes, traffic.UploadBytes+traffic.DownloadBytes)
	}
}
