package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type ReportType string

const (
	TypeIncident    ReportType = "Incident"
	TypeExecutive   ReportType = "Executive"
	TypeTimeline    ReportType = "Timeline"
	TypeMitre       ReportType = "MITRE"
	TypeIoc         ReportType = "IOC"
	TypeThreat      ReportType = "Threat"
	TypePerformance ReportType = "Performance"
	TypeHealth      ReportType = "Health"
)

type ReportFormat string

const (
	FormatJSON ReportFormat = "JSON"
	FormatHTML ReportFormat = "HTML"
	FormatPDF  ReportFormat = "PDF"
	FormatCSV  ReportFormat = "CSV"
)

type ReportData struct {
	Timestamp      time.Time        `json:"timestamp"`
	Title          string           `json:"title"`
	Summary        string           `json:"summary"`
	AlertCount     int              `json:"alert_count"`
	MaxRiskScore   float64          `json:"max_risk_score"`
	MitreTags      []string         `json:"mitre_tags"`
	TimelineEvents []string         `json:"timeline_events"`
	IocMatches     []string         `json:"ioc_matches"`
	CPUUsage       float64          `json:"cpu_usage"`
	MemoryMB       uint64           `json:"memory_mb"`
	DatabaseSizeKB int64            `json:"database_size_kb"`
	Status         string           `json:"status"`
}

type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

func (g *Generator) Generate(repType ReportType, format ReportFormat, data *ReportData) ([]byte, error) {
	data.Title = fmt.Sprintf("AEGIS EDR %s Report", string(repType))
	data.Timestamp = time.Now()

	switch format {
	case FormatJSON:
		return json.MarshalIndent(data, "", "  ")

	case FormatHTML:
		return g.generateHTML(repType, data), nil

	case FormatCSV:
		return g.generateCSV(repType, data), nil

	case FormatPDF:
		return g.generatePDF(repType, data), nil
	}

	return nil, fmt.Errorf("unsupported report format: %s", format)
}

func (g *Generator) generateHTML(repType ReportType, data *ReportData) []byte {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>%s</title>
<style>
body { font-family: sans-serif; margin: 30px; background-color: #f7f9fa; color: #333; }
h1 { color: #1a73e8; }
.card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
.meta { color: #666; font-size: 0.9em; }
</style>
</head>
<body>
<h1>%s</h1>
<div class="meta">Generated: %s</div>
<div class="card">
<h2>Executive Summary</h2>
<p>%s</p>
<p>Alerts Triggered: <strong>%d</strong> (Max Risk Score: <strong>%.2f</strong>)</p>
<p>System Status: <strong>%s</strong></p>
</div>
`, data.Title, data.Title, data.Timestamp.Format(time.RFC3339), data.Summary, data.AlertCount, data.MaxRiskScore, data.Status)

	if len(data.TimelineEvents) > 0 {
		html += `<div class="card"><h2>Timeline Logs</h2><ul>`
		for _, ev := range data.TimelineEvents {
			html += fmt.Sprintf("<li>%s</li>", ev)
		}
		html += `</ul></div>`
	}

	if len(data.MitreTags) > 0 {
		html += `<div class="card"><h2>MITRE ATT&CK Mappings</h2><ul>`
		for _, tag := range data.MitreTags {
			html += fmt.Sprintf("<li>%s</li>", tag)
		}
		html += `</ul></div>`
	}

	if len(data.IocMatches) > 0 {
		html += `<div class="card"><h2>IOC Matches</h2><ul>`
		for _, ioc := range data.IocMatches {
			html += fmt.Sprintf("<li>%s</li>", ioc)
		}
		html += `</ul></div>`
	}

	html += `</body></html>`
	return []byte(html)
}

func (g *Generator) generateCSV(repType ReportType, data *ReportData) []byte {
	var sb strings.Builder
	sb.WriteString("Parameter,Value\n")
	sb.WriteString(fmt.Sprintf("Report Title,%s\n", data.Title))
	sb.WriteString(fmt.Sprintf("Generated At,%s\n", data.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Alerts,%d\n", data.AlertCount))
	sb.WriteString(fmt.Sprintf("Max Risk Score,%.2f\n", data.MaxRiskScore))
	sb.WriteString(fmt.Sprintf("CPU Usage %%,%.2f\n", data.CPUUsage))
	sb.WriteString(fmt.Sprintf("Memory Usage MB,%d\n", data.MemoryMB))
	sb.WriteString(fmt.Sprintf("Status,%s\n", data.Status))
	return []byte(sb.String())
}

func (g *Generator) generatePDF(repType ReportType, data *ReportData) []byte {
	txt := fmt.Sprintf("AEGIS %s Report Generated: %s\nSummary: %s\nAlerts: %d\nRisk: %.2f\nStatus: %s",
		string(repType), data.Timestamp.Format(time.RFC3339), data.Summary, data.AlertCount, data.MaxRiskScore, data.Status)

	pdf := fmt.Sprintf("%%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << >> /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n0000000056 00000 n\n0000000111 00000 n\n0000000196 00000 n\ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n310\n%%EOF\n",
		len(txt), txt)

	return []byte(pdf)
}
