//go:build windows

package network

import (
	"os/exec"
)

type WindowsIsolator struct{}

func newNetworkIsolator() NetworkIsolator {
	return &WindowsIsolator{}
}

func (i *WindowsIsolator) IsolateHost() error {
	cmd := exec.Command("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")
	return cmd.Run()
}

func (i *WindowsIsolator) RestoreHost() error {
	cmd := exec.Command("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
	return cmd.Run()
}
