//go:build linux

package network

import (
	"os/exec"
)

type LinuxIsolator struct{}

func newNetworkIsolator() NetworkIsolator {
	return &LinuxIsolator{}
}

func (i *LinuxIsolator) IsolateHost() error {
	cmd := exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "8443", "-j", "ACCEPT")
	_ = cmd.Run()
	cmd = exec.Command("iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
	_ = cmd.Run()
	cmd = exec.Command("iptables", "-P", "OUTPUT", "DROP")
	return cmd.Run()
}

func (i *LinuxIsolator) RestoreHost() error {
	cmd := exec.Command("iptables", "-P", "OUTPUT", "ACCEPT")
	_ = cmd.Run()
	cmd = exec.Command("iptables", "-F", "OUTPUT")
	return cmd.Run()
}
