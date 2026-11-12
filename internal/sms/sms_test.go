package sms

import (
	"testing"
)

func TestProviderNames(t *testing.T) {
	g := NewGrizzly("dummy")
	if g.Name() != "grizzly" {
		t.Errorf("name = %q", g.Name())
	}

	f := NewFiveSim("dummy")
	if f.Name() != "5sim" {
		t.Errorf("name = %q", f.Name())
	}

	l := NewLocalL("http://127.0.0.1:8788", "token")
	if l.Name() != "l" {
		t.Errorf("name = %q", l.Name())
	}
}
