package process

import (
	"os/exec"
	"testing"
	"time"
)

func TestKillTree(t *testing.T) {
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep process: %v", err)
	}

	pid := cmd.Process.Pid
	killer := NewProcessTreeKiller()

	time.Sleep(100 * time.Millisecond)

	if err := killer.KillTree(pid); err != nil {
		t.Fatalf("failed to kill process tree: %v", err)
	}

	err := cmd.Wait()
	if err == nil {
		t.Error("expected process to be terminated, got clean exit")
	}
}
