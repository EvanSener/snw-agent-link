package tailscale

import (
	"errors"
	"fmt"
	"net/netip"
)

var (
	ErrInvalidAddress      = errors.New("invalid IP address")
	ErrNotTailscaleAddress = errors.New("address is not assigned by Tailscale")
)

var (
	tailscaleIPv4 = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleIPv6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

type AddressPolicy struct {
	allowedPrefixes []netip.Prefix
}

func DefaultAddressPolicy() AddressPolicy {
	return AddressPolicy{allowedPrefixes: []netip.Prefix{tailscaleIPv4, tailscaleIPv6}}
}

func (p AddressPolicy) ValidateBindAddress(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %q", ErrInvalidAddress, value)
	}
	address = address.Unmap()
	for _, prefix := range p.allowedPrefixes {
		if prefix.Contains(address) {
			return address, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: %s", ErrNotTailscaleAddress, address)
}
