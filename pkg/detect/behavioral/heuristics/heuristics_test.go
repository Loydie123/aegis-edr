package heuristics

import (
	"strings"
	"testing"
)

func TestParseMapsAndDetect(t *testing.T) {
	t.Parallel()

	input := `
00400000-00452000 r-xp 00000000 08:02 173832      /bin/ls
00652000-00655000 rw-p 00052000 08:02 173832      /bin/ls
7ffdd9dfd000-7ffdd9e1e000 rwxp 00000000 00:00 0   [stack]
`

	regions, err := ParseMaps(strings.NewReader(input))
	if err != nil {
		t.Fatalf("failed to parse maps: %v", err)
	}

	if len(regions) != 3 {
		t.Fatalf("expected 3 regions, got %d", len(regions))
	}

	if regions[0].Permissions != "r-xp" {
		t.Errorf("expected permissions r-xp, got %s", regions[0].Permissions)
	}
	if regions[2].Path != "[stack]" {
		t.Errorf("expected path [stack], got %s", regions[2].Path)
	}

	suspicious := DetectSuspiciousRegions(regions)
	if len(suspicious) != 1 {
		t.Fatalf("expected 1 suspicious region, got %d", len(suspicious))
	}

	if suspicious[0].Start != 0x7ffdd9dfd000 {
		t.Errorf("expected start address 0x7ffdd9dfd000, got 0x%x", suspicious[0].Start)
	}
}
