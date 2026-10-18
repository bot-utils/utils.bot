package main

import (
	"reflect"
	"testing"
)

func TestPrivateNetworkChecksFollowDeployedIngressPorts(t *testing.T) {
	for resource, want := range map[string][]string{
		"https://utils.bot/v1/pdf/text":     {"https://origin.utils.bot/health"},
		"https://api.utils.bot/v1/pdf/text": {"https://origin.utils.bot:8443/health", "https://api.utils.bot/v1/pdf/text"},
	} {
		got, valid := privateNetworkTargets(resource)
		if !valid || !reflect.DeepEqual(got, want) {
			t.Fatalf("independent probe misses a deployed private listener: %s: %v", resource, got)
		}
	}
}

func TestPrivateNetworkChecksRejectUnownedTargets(t *testing.T) {
	for _, resource := range []string{"", "http://api.utils.bot/v1/pdf/text", "https://api.utils.bot.attacker.test/v1/pdf/text", "https://attacker.test/v1/pdf/text", "https://api.utils.bot/v1/pdf/text?redirect=1"} {
		if got, valid := privateNetworkTargets(resource); valid || got != nil {
			t.Fatal("validation image can probe an unapproved target", resource)
		}
	}
}
