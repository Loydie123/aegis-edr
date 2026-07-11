//go:build darwin

package network

import (
	"os/exec"
)

type DarwinIsolator struct{}

func newNetworkIsolator() NetworkIsolator {
	return &DarwinIsolator{}
}

func (i *DarwinIsolator) IsolateHost() error {
	cmd := exec.Command("pfctl", "-e")
	return cmd.Run()
}

func (i *DarwinIsolator) RestoreHost() error {
	cmd := exec.Command("pfctl", "-d")
	return cmd.Run()
}
