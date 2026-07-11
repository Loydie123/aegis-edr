package storage

import (
	"context"
	"database/sql"

	_ "modernc.org/sqlite"
)

type Storage struct {
	db *sql.DB
}

func NewStorage(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	s := &Storage{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) DB() *sql.DB {
	return s.db
}

func (s *Storage) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS processes (
			process_id INTEGER PRIMARY KEY AUTOINCREMENT,
			parent_id INTEGER,
			binary_path TEXT NOT NULL,
			sha256 TEXT NOT NULL,
			command_line TEXT NOT NULL,
			username TEXT NOT NULL,
			launched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS file_modifications (
			event_id INTEGER PRIMARY KEY AUTOINCREMENT,
			process_id INTEGER,
			file_path TEXT NOT NULL,
			action TEXT NOT NULL,
			occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(process_id) REFERENCES processes(process_id)
		);`,
		`CREATE TABLE IF NOT EXISTS network_connections (
			connection_id INTEGER PRIMARY KEY AUTOINCREMENT,
			process_id INTEGER,
			protocol TEXT NOT NULL,
			local_ip TEXT NOT NULL,
			local_port INTEGER NOT NULL,
			remote_ip TEXT NOT NULL,
			remote_port INTEGER NOT NULL,
			occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(process_id) REFERENCES processes(process_id)
		);`,
		`CREATE TABLE IF NOT EXISTS alert_logs (
			alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_name TEXT NOT NULL,
			category TEXT NOT NULL,
			risk_score REAL NOT NULL,
			description TEXT NOT NULL,
			process_id INTEGER,
			triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(process_id) REFERENCES processes(process_id)
		);`,
		`CREATE TABLE IF NOT EXISTS indicators (
			indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
			pattern TEXT NOT NULL,
			pattern_type TEXT NOT NULL,
			threat_label TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_processes_launched_at ON processes(launched_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_file_path ON file_modifications(file_path);`,
		`CREATE INDEX IF NOT EXISTS idx_network_dest ON network_connections(remote_ip, remote_port);`,
		`CREATE INDEX IF NOT EXISTS idx_processes_sha256 ON processes(sha256);`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

func (s *Storage) InsertProcess(ctx context.Context, parentID int, binaryPath, sha256, commandLine, username string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO processes (parent_id, binary_path, sha256, command_line, username) VALUES (?, ?, ?, ?, ?)",
		parentID, binaryPath, sha256, commandLine, username,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Storage) InsertFileModification(ctx context.Context, processID int, filePath, action string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO file_modifications (process_id, file_path, action) VALUES (?, ?, ?)",
		processID, filePath, action,
	)
	return err
}

func (s *Storage) InsertNetworkConnection(ctx context.Context, processID int, protocol, localIP string, localPort int, remoteIP string, remotePort int) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO network_connections (process_id, protocol, local_ip, local_port, remote_ip, remote_port) VALUES (?, ?, ?, ?, ?, ?)",
		processID, protocol, localIP, localPort, remoteIP, remotePort,
	)
	return err
}

func (s *Storage) InsertAlertLog(ctx context.Context, ruleName, category string, riskScore float64, description string, processID int) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO alert_logs (rule_name, category, risk_score, description, process_id) VALUES (?, ?, ?, ?, ?)",
		ruleName, category, riskScore, description, processID,
	)
	return err
}
