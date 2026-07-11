//go:build windows

package process

import (
	"os"
)

type WindowsProcessTreeKiller struct{}

func newProcessTreeKiller() ProcessTreeKiller {
	return &WindowsProcessTreeKiller{}
}

func (k *WindowsProcessTreeKiller) KillTree(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}
