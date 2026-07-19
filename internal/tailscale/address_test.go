package tailscale

import (
	"errors"
	"testing"
)

func TestDefaultAddressPolicyAllowsOnlyTailscaleAddresses(t *testing.T) {
	policy := DefaultAddressPolicy()

	for _, address := range []string{"100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::1"} {
		if _, err := policy.ValidateBindAddress(address); err != nil {
			t.Fatalf("expected %s to be accepted: %v", address, err)
		}
	}

	for _, address := range []string{"0.0.0.0", "127.0.0.1", "192.168.1.10", "8.8.8.8", "::", "::1", "fd00::1"} {
		if _, err := policy.ValidateBindAddress(address); !errors.Is(err, ErrNotTailscaleAddress) {
			t.Fatalf("expected %s to be rejected, got %v", address, err)
		}
	}
}

func TestAddressPolicyRejectsInvalidInput(t *testing.T) {
	if _, err := DefaultAddressPolicy().ValidateBindAddress("not-an-ip"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("expected invalid address error, got %v", err)
	}
}
