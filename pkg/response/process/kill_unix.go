//go:build linux || darwin

package process

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

type UnixProcessTreeKiller struct{}

func newProcessTreeKiller() ProcessTreeKiller {
	return &UnixProcessTreeKiller{}
}

func (k *UnixProcessTreeKiller) KillTree(pid int) error {
	pids, err := k.findChildPIDs(pid)
	if err == nil {
		for _, child := range pids {
			_ = k.KillTree(child)
		}
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	return proc.Signal(syscall.SIGKILL)
}

func (k *UnixProcessTreeKiller) findChildPIDs(ppid int) ([]int, error) {
	cmd := exec.Command("pgrep", "-P", strconv.Itoa(ppid))
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var pids []int
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		child, err := strconv.Atoi(trimmed)
		if err == nil {
			pids = append(pids, child)
		}
	}
	return pids, nil
}
