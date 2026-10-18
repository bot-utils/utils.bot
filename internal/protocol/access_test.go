package protocol

import "testing"

func TestPublicAccessRequiresAnExplicitValidMainnetSetting(t *testing.T) {
	for _, mode := range []string{ModeMock, ModeSepolia, ModeBase} {
		payTo := "0x2222222222222222222222222222222222222222"
		if mode == ModeMock {
			payTo = ""
		}
		cfg, err := NewConfig(mode, payTo)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PublicAccess() {
			t.Fatal("payment mode exposed service")
		}
		for _, bad := range []string{"true", "yes", "2", " 1"} {
			if _, err := cfg.WithPublicAccess(bad); err == nil {
				t.Fatal("malformed launch setting", bad)
			}
		}
		public, err := cfg.WithPublicAccess("1")
		if mode != ModeBase {
			if err == nil {
				t.Fatal("test payments exposed publicly")
			}
			continue
		}
		if err != nil || !public.PublicAccess() {
			t.Fatal("mainnet launch unavailable", err)
		}
		if cfg.PublicAccess() {
			t.Fatal("configuration mutated")
		}
		private, err := public.WithPublicAccess("0")
		if err != nil || private.PublicAccess() {
			t.Fatal("cannot return private")
		}
	}
}
