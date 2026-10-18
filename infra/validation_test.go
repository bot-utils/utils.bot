package main

import "testing"

func TestValidationImageCannotBecomeDefaultOrTargetLocalAccounts(t *testing.T) {
	t.Setenv("PDF_DEPLOY_ACCOUNT_ID", "111111111111")
	if serverImageTarget("", "111111111111", false, true, false) != "runtime" {
		t.Fatal("normal deployments include validation code")
	}
	if serverImageTarget("1", "111111111111", false, true, false) != "private-edge-check" {
		t.Fatal("explicit private check missing")
	}
	for _, tc := range []struct {
		account     string
		local, edge bool
	}{{"000000000000", true, true}, {"111111111111", false, false}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("unsafe validation target accepted")
				}
			}()
			serverImageTarget("1", tc.account, tc.local, tc.edge, false)
		}()
	}
}

func TestIndependentValidationImageCannotBePublic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("private validation image accepted for a public deployment")
		}
	}()
	serverImageTarget("1", "111111111111", false, true, true)
}
