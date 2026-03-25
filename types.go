package main

import "time"

// Peer represents a registered Claude Code instance.
type Peer struct {
	ID           string `json:"id"`
	PID          int    `json:"pid"`
	CWD          string `json:"cwd"`
	GitRoot      string `json:"git_root"`
	TTY          string `json:"tty"`
	Summary      string `json:"summary"`
	RegisteredAt string `json:"registered_at"`
	LastSeen     string `json:"last_seen"`
}

// Message is a queued message between peers.
type Message struct {
	ID        int    `json:"id"`
	FromID    string `json:"from_id"`
	ToID      string `json:"to_id"`
	Text      string `json:"text"`
	SentAt    string `json:"sent_at"`
	Delivered bool   `json:"delivered"`
}

// --- Broker API request/response types ---

type RegisterRequest struct {
	PID     int    `json:"pid"`
	CWD     string `json:"cwd"`
	GitRoot string `json:"git_root"`
	TTY     string `json:"tty"`
	Summary string `json:"summary"`
}

type RegisterResponse struct {
	ID string `json:"id"`
}

type HeartbeatRequest struct {
	ID string `json:"id"`
}

type SetSummaryRequest struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type ListPeersRequest struct {
	Scope     string `json:"scope"`
	CWD       string `json:"cwd"`
	GitRoot   string `json:"git_root"`
	ExcludeID string `json:"exclude_id"`
}

type SendMessageRequest struct {
	FromID string `json:"from_id"`
	ToID   string `json:"to_id"`
	Text   string `json:"text"`
}

type SendMessageResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type PollMessagesRequest struct {
	ID string `json:"id"`
}

type PollMessagesResponse struct {
	Messages []Message `json:"messages"`
}

type UnregisterRequest struct {
	ID string `json:"id"`
}

type HealthResponse struct {
	Status string `json:"status"`
	Peers  int    `json:"peers"`
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}
