package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Result holds the scan result for a single IP address.
type Result struct {
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	IsReality   bool      `json:"is_reality"`
	ServerName  string    `json:"server_name,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Country     string    `json:"country,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	Latency     int64     `json:"latency_ms"`
	ScannedAt   time.Time `json:"scanned_at"`
	Error       string    `json:"error,omitempty"`
}

// ResultWriter handles thread-safe writing of scan results to output.
type ResultWriter struct {
	mu       sync.Mutex
	file     *os.File
	encoder  *json.Encoder
	count    int
	filePath string
}

// NewResultWriter creates a new ResultWriter that writes JSON lines to the given file path.
// If filePath is empty, results are written to stdout.
func NewResultWriter(filePath string) (*ResultWriter, error) {
	var f *os.File
	var err error

	if filePath == "" {
		f = os.Stdout
	} else {
		f, err = os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open output file %s: %w", filePath, err)
		}
	}

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)

	return &ResultWriter{
		file:     f,
		encoder:  enc,
		filePath: filePath,
	}, nil
}

// Write appends a Result to the output in JSON Lines format.
// This method is safe for concurrent use.
func (rw *ResultWriter) Write(r *Result) error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if err := rw.encoder.Encode(r); err != nil {
		return fmt.Errorf("failed to write result for %s: %w", r.IP, err)
	}
	rw.count++
	return nil
}

// Count returns the total number of results written so far.
func (rw *ResultWriter) Count() int {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.count
}

// Close flushes and closes the underlying file if it is not stdout.
func (rw *ResultWriter) Close() error {
	if rw.file != nil && rw.file != os.Stdout {
		return rw.file.Close()
	}
	return nil
}

// Summary prints a brief scan summary to stderr.
func (rw *ResultWriter) Summary(total int, duration time.Duration) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	fmt.Fprintf(os.Stderr, "\n--- Scan Summary ---\n")
	fmt.Fprintf(os.Stderr, "Total scanned : %d\n", total)
	fmt.Fprintf(os.Stderr, "Reality found : %d\n", rw.count)
	fmt.Fprintf(os.Stderr, "Duration      : %s\n", duration.Round(time.Millisecond))
	if rw.filePath != "" {
		fmt.Fprintf(os.Stderr, "Output file   : %s\n", rw.filePath)
	}
}
