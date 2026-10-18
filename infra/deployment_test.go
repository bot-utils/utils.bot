package main

import "testing"

func TestAccountGuardDoesNotDefaultToAnyRealAccount(t *testing.T) {
	t.Setenv("PDF_DEPLOY_ACCOUNT_ID", "111111111111")
	requireDeploymentAccount("111111111111", false)
	requireDeploymentAccount("000000000000", true)
	for _, value := range []string{"", "000000000000", "222222222222", "not-an-account"} {
		t.Run(value, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("wrong account accepted")
				}
			}()
			requireDeploymentAccount(value, false)
		})
	}
	t.Setenv("PDF_DEPLOY_ACCOUNT_ID", "")
	defer func() {
		if recover() == nil {
			t.Fatal("missing expected account accepted")
		}
	}()
	requireDeploymentAccount("111111111111", false)
}

func TestAlarmRecipientMustBeAnExplicitPlainAddress(t *testing.T) {
	t.Setenv("PDF_ALERT_EMAIL", "ops@example.test")
	if alertEmail() != "ops@example.test" {
		t.Fatal("recipient changed")
	}
	for _, value := range []string{"", "Operator <ops@example.test>", "ops@example.test\r\nBcc: other@example.test"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("PDF_ALERT_EMAIL", value)
			defer func() {
				if recover() == nil {
					t.Fatal("unsafe or missing recipient accepted")
				}
			}()
			alertEmail()
		})
	}
}

func TestHostedZoneHasNoOperatorSpecificDefault(t *testing.T) {
	t.Setenv("PDF_HOSTED_ZONE_ID", "ZEXAMPLEDNS")
	if hostedZoneID() != "ZEXAMPLEDNS" {
		t.Fatal("zone changed")
	}
	t.Setenv("PDF_HOSTED_ZONE_ID", "")
	defer func() {
		if recover() == nil {
			t.Fatal("missing zone silently accepted")
		}
	}()
	hostedZoneID()
}
