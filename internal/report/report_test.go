package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReportGeneration(t *testing.T) {
	generator := NewGenerator()

	data := &ReportData{
		Summary:      "Suspicious powershell activity detected",
		AlertCount:   2,
		MaxRiskScore: 0.85,
		MitreTags:    []string{"T1059.001", "T1071.001"},
		TimelineEvents: []string{
			"powershell.exe executed with suspicious bypass options",
			"Socket connection opened to external IP",
		},
		IocMatches: []string{"db29f03225d369f17089b2bbecdd3d80617"},
		CPUUsage:   12.4,
		MemoryMB:   84,
		Status:     "healthy",
	}

	types := []ReportType{
		TypeIncident,
		TypeExecutive,
		TypeTimeline,
		TypeMitre,
		TypeIoc,
		TypeThreat,
		TypePerformance,
		TypeHealth,
	}

	formats := []ReportFormat{
		FormatJSON,
		FormatHTML,
		FormatCSV,
		FormatPDF,
	}

	for _, repType := range types {
		for _, format := range formats {
			out, err := generator.Generate(repType, format, data)
			if err != nil {
				t.Fatalf("failed to generate %s in %s: %v", repType, format, err)
			}

			if len(out) == 0 {
				t.Errorf("empty report for %s in %s", repType, format)
			}

			switch format {
			case FormatJSON:
				var parsed ReportData
				if errJson := json.Unmarshal(out, &parsed); errJson != nil {
					t.Errorf("invalid JSON generated: %v", errJson)
				}

			case FormatHTML:
				outStr := string(out)
				if !strings.Contains(outStr, "<html>") || !strings.Contains(outStr, "Suspicious powershell activity") {
					t.Errorf("HTML format missing mandatory structure or text content")
				}

			case FormatCSV:
				outStr := string(out)
				if !strings.Contains(outStr, "Parameter,Value") || !strings.Contains(outStr, "healthy") {
					t.Errorf("CSV format missing CSV headers or content values")
				}

			case FormatPDF:
				outStr := string(out)
				if !strings.HasPrefix(outStr, "%PDF-") || !strings.Contains(outStr, "%EOF") {
					t.Errorf("PDF format missing valid magic header or EOF tokens")
				}
			}
		}
	}
}
