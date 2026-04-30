package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ScanResult holds the result of a TLS scan for a single host.
type ScanResult struct {
	IP          string
	Port        int
	Domain      string
	HasRealityX bool
	Cert        *tls.Certificate
	TLSVersion  uint16
	CipherSuite uint16
	Error       error
}

// Scanner performs TLS handshake scans against target hosts.
type Scanner struct {
	Timeout     time.Duration
	Workers     int
	ServerName  string
	Results     chan ScanResult
}

// NewScanner creates a new Scanner with the given configuration.
func NewScanner(serverName string, timeout time.Duration, workers int) *Scanner {
	return &Scanner{
		Timeout:    timeout,
		Workers:    workers,
		ServerName: serverName,
		Results:    make(chan ScanResult, workers*2),
	}
}

// Scan performs a TLS scan against the given IP and port.
// It attempts a TLS handshake and checks for REALITY extension indicators.
func (s *Scanner) Scan(ip string, port int) ScanResult {
	result := ScanResult{
		IP:   ip,
		Port: port,
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	dialer := &net.Dialer{Timeout: s.Timeout}

	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		result.Error = fmt.Errorf("tcp dial failed: %w", err)
		return result
	}
	defer rawConn.Close()

	rawConn.SetDeadline(time.Now().Add(s.Timeout))

	tlsConfig := &tls.Config{
		ServerName:         s.ServerName,
		InsecureSkipVerify: true, // We want to inspect even self-signed / REALITY certs
		MinVersion:         tls.VersionTLS13,
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		result.Error = fmt.Errorf("tls handshake failed: %w", err)
		return result
	}

	state := tlsConn.ConnectionState()
	result.TLSVersion = state.Version
	result.CipherSuite = state.CipherSuite

	// REALITY detection: REALITY servers present a valid-looking TLS 1.3 cert
	// but the certificate will not chain to a trusted CA and will have
	// specific characteristics. We flag TLS 1.3 connections with unverified
	// certificate chains as potential REALITY endpoints.
	if state.Version == tls.VersionTLS13 && len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Domain = cert.Subject.CommonName
		result.HasRealityX = isLikelyReality(state)
	}

	return result
}

// ScanWorker reads IPs from the jobs channel and sends results to s.Results.
func (s *Scanner) ScanWorker(jobs <-chan string, port int, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	for ip := range jobs {
		s.Results <- s.Scan(ip, port)
	}
}

// isLikelyReality heuristically determines whether a TLS connection state
// looks like a REALITY proxy endpoint.
// REALITY endpoints use TLS 1.3 and typically present certificates that
// don't verify against system roots but are otherwise well-formed.
func isLikelyReality(state tls.ConnectionState) bool {
	if state.Version != tls.VersionTLS13 {
		return false
	}
	if len(state.PeerCertificates) == 0 {
		return false
	}
	// If the certificate chain was not verified (InsecureSkipVerify was set),
	// and the handshake succeeded with TLS 1.3, it's a candidate.
	// Additional fingerprinting can be added here (e.g., cert SANs, issuer).
	return !state.HandshakeComplete || state.VerifiedChains == nil
}
