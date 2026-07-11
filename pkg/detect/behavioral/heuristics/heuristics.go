package heuristics

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type MemoryRegion struct {
	Start       uint64
	End         uint64
	Permissions string
	Path        string
}

func ScanProcessMaps(pid int) ([]MemoryRegion, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ParseMaps(file)
}

func ParseMaps(r io.Reader) ([]MemoryRegion, error) {
	var regions []MemoryRegion
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		addrRange := strings.Split(fields[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		var start, end uint64
		_, _ = fmt.Sscanf(addrRange[0], "%x", &start)
		_, _ = fmt.Sscanf(addrRange[1], "%x", &end)

		perms := fields[1]
		path := ""
		if len(fields) >= 6 {
			path = fields[5]
		}

		regions = append(regions, MemoryRegion{
			Start:       start,
			End:         end,
			Permissions: perms,
			Path:        path,
		})
	}

	return regions, scanner.Err()
}

func DetectSuspiciousRegions(regions []MemoryRegion) []MemoryRegion {
	var suspicious []MemoryRegion
	for _, r := range regions {
		if strings.Contains(r.Permissions, "w") && strings.Contains(r.Permissions, "x") {
			suspicious = append(suspicious, r)
		}
	}
	return suspicious
}
