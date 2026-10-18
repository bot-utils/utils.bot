package main

import (
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/jsii-runtime-go"
)

func TestPrototypeIngressRequiresOneIPv4Address(t *testing.T) {
	for _, value := range []string{"203.0.113.10/32", "203.0.113.10/32"} {
		if !ownerCIDR(value) {
			t.Fatal("valid owner address rejected", value)
		}
	}
	for _, value := range []string{"", "0.0.0.0/0", "203.0.113.0/24", "203.0.113.10", "::/0", "2001:db8::1/128", "invalid"} {
		if ownerCIDR(value) {
			t.Fatal("prototype ingress widened", value)
		}
	}
}

func TestPrototypeDefaultsStopped(t *testing.T) {
	for _, value := range []string{"", "0"} {
		if prototypeDesiredCount(value) != 0 {
			t.Fatal("deployment would restart stopped prototype")
		}
	}
	if prototypeDesiredCount("1") != 1 {
		t.Fatal("explicit single-task restart rejected")
	}
	if prototypeDesiredCount("2") != 2 {
		t.Fatal("autoscaler-selected second task rejected")
	}
	for _, value := range []string{"3", "-1", "invalid"} {
		t.Run(value, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("unexpected prototype task count accepted")
				}
			}()
			prototypeDesiredCount(value)
		})
	}
}

func TestAutoscalingCannotWakeStoppedServiceOrExceedTwoTasks(t *testing.T) {
	if autoscalingSetting("0", "0") || autoscalingSetting("", "1") {
		t.Fatal("autoscaling enabled without explicit opt-in")
	}
	for _, desired := range []string{"1", "2"} {
		if !autoscalingSetting("1", desired) || serviceDesiredCount(desired, true) != nil {
			t.Fatal("active autoscaling should leave desired count under scaler control", desired)
		}
	}
	for _, test := range []struct{ enabled, desired string }{{"1", "0"}, {"0", "2"}, {"2", "1"}} {
		t.Run(test.enabled+test.desired, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("unsafe autoscaling combination accepted")
				}
			}()
			autoscalingSetting(test.enabled, test.desired)
		})
	}
}

func TestAutoscalingConfiguredIntentIsExplicit(t *testing.T) {
	if autoscalingConfiguredSetting("") || autoscalingConfiguredSetting("0") {
		t.Fatal("missing or explicit zero intent enabled autoscaling")
	}
	if !autoscalingConfiguredSetting("1") {
		t.Fatal("configured autoscaling intent rejected")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("invalid configured autoscaling intent accepted")
		}
	}()
	autoscalingConfiguredSetting("invalid")
}

func TestPrivateRollingDeploymentCannotExceedDesiredTaskCount(t *testing.T) {
	minimum, maximum := boundedDeploymentPercentages(false)
	if minimum != 0 || maximum != 100 {
		t.Fatal("rolling deployment can temporarily exceed the two-task cost cap", minimum, maximum)
	}
}

func TestLiveRollingDeploymentKeepsHealthyCapacity(t *testing.T) {
	minimum, maximum := boundedDeploymentPercentages(true)
	if minimum != 100 || maximum != 200 {
		t.Fatal("live deployment must preserve healthy tasks and allow replacements", minimum, maximum)
	}
}

func TestPublicAccessIsExplicitAndMainnetOnly(t *testing.T) {
	if publicAccessSetting("", "cdp-base") || publicAccessSetting("0", "cdp-base") {
		t.Fatal("deployment defaults public")
	}
	if !publicAccessSetting("1", "cdp-base") {
		t.Fatal("explicit mainnet launch refused")
	}
	for _, test := range []struct{ setting, mode string }{{"true", "cdp-base"}, {"1", "mock"}, {"1", "cdp-base-sepolia"}, {"2", "cdp-base"}} {
		t.Run(test.setting+test.mode, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("unsafe public setting accepted")
				}
			}()
			publicAccessSetting(test.setting, test.mode)
		})
	}
}

func TestRealStacksEnableTerminationProtectionButLocalStackStaysDisposable(t *testing.T) {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	real := awscdk.NewStack(app, jsii.String("Real"), &awscdk.StackProps{TerminationProtection: stackTerminationProtection(false)})
	local := awscdk.NewStack(app, jsii.String("Local"), &awscdk.StackProps{TerminationProtection: stackTerminationProtection(true)})
	app.Synth(nil)
	if real.TerminationProtection() == nil || !*real.TerminationProtection() {
		t.Fatal("real deployment can be deleted without first disabling stack termination protection")
	}
	if local.TerminationProtection() == nil || *local.TerminationProtection() {
		t.Fatal("LocalStack cleanup is blocked by production termination protection")
	}
}
