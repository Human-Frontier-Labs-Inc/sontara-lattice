package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

func brokerDBPath() string {
	if p := os.Getenv("CLAUDE_PEERS_DB"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude-peers.db")
}

func brokerPort() string {
	if p := os.Getenv("CLAUDE_PEERS_PORT"); p != "" {
		return p
	}
	return "7899"
}

func generatePeerID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func pidAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

type Broker struct {
	db *sql.DB
	mu sync.RWMutex
}

func newBroker() (*Broker, error) {
	db, err := sql.Open("sqlite", brokerDBPath()+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(3000)")
	if err != nil {
		return nil, err
	}

	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS peers (
			id TEXT PRIMARY KEY,
			pid INTEGER NOT NULL,
			cwd TEXT NOT NULL,
			git_root TEXT,
			tty TEXT,
			summary TEXT NOT NULL DEFAULT '',
			registered_at TEXT NOT NULL,
			last_seen TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			from_id TEXT NOT NULL,
			to_id TEXT NOT NULL,
			text TEXT NOT NULL,
			sent_at TEXT NOT NULL,
			delivered INTEGER NOT NULL DEFAULT 0
		)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return nil, fmt.Errorf("schema: %w", err)
		}
	}

	b := &Broker{db: db}
	b.cleanStalePeers()
	return b, nil
}

func (b *Broker) cleanStalePeers() {
	rows, err := b.db.Query("SELECT id, pid FROM peers")
	if err != nil {
		return
	}
	defer rows.Close()

	var stale []string
	for rows.Next() {
		var id string
		var pid int
		rows.Scan(&id, &pid)
		if !pidAlive(pid) {
			stale = append(stale, id)
		}
	}

	for _, id := range stale {
		b.db.Exec("DELETE FROM peers WHERE id = ?", id)
		b.db.Exec("DELETE FROM messages WHERE to_id = ? AND delivered = 0", id)
	}
}

func (b *Broker) register(req RegisterRequest) RegisterResponse {
	id := generatePeerID()
	now := nowISO()

	// Remove existing registration for same PID
	b.db.Exec("DELETE FROM peers WHERE pid = ?", req.PID)

	b.db.Exec(
		"INSERT INTO peers (id, pid, cwd, git_root, tty, summary, registered_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		id, req.PID, req.CWD, req.GitRoot, req.TTY, req.Summary, now, now,
	)
	return RegisterResponse{ID: id}
}

func (b *Broker) heartbeat(req HeartbeatRequest) {
	b.db.Exec("UPDATE peers SET last_seen = ? WHERE id = ?", nowISO(), req.ID)
}

func (b *Broker) setSummary(req SetSummaryRequest) {
	b.db.Exec("UPDATE peers SET summary = ? WHERE id = ?", req.Summary, req.ID)
}

func (b *Broker) listPeers(req ListPeersRequest) []Peer {
	var query string
	var args []any

	switch req.Scope {
	case "directory":
		query = "SELECT id, pid, cwd, git_root, tty, summary, registered_at, last_seen FROM peers WHERE cwd = ?"
		args = []any{req.CWD}
	case "repo":
		if req.GitRoot != "" {
			query = "SELECT id, pid, cwd, git_root, tty, summary, registered_at, last_seen FROM peers WHERE git_root = ?"
			args = []any{req.GitRoot}
		} else {
			query = "SELECT id, pid, cwd, git_root, tty, summary, registered_at, last_seen FROM peers WHERE cwd = ?"
			args = []any{req.CWD}
		}
	default:
		query = "SELECT id, pid, cwd, git_root, tty, summary, registered_at, last_seen FROM peers"
	}

	rows, err := b.db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var peers []Peer
	for rows.Next() {
		var p Peer
		var gitRoot, tty sql.NullString
		rows.Scan(&p.ID, &p.PID, &p.CWD, &gitRoot, &tty, &p.Summary, &p.RegisteredAt, &p.LastSeen)
		p.GitRoot = gitRoot.String
		p.TTY = tty.String

		if req.ExcludeID != "" && p.ID == req.ExcludeID {
			continue
		}
		if !pidAlive(p.PID) {
			b.db.Exec("DELETE FROM peers WHERE id = ?", p.ID)
			continue
		}
		peers = append(peers, p)
	}
	return peers
}

func (b *Broker) sendMessage(req SendMessageRequest) SendMessageResponse {
	var exists bool
	b.db.QueryRow("SELECT EXISTS(SELECT 1 FROM peers WHERE id = ?)", req.ToID).Scan(&exists)
	if !exists {
		return SendMessageResponse{OK: false, Error: fmt.Sprintf("Peer %s not found", req.ToID)}
	}
	b.db.Exec(
		"INSERT INTO messages (from_id, to_id, text, sent_at, delivered) VALUES (?, ?, ?, ?, 0)",
		req.FromID, req.ToID, req.Text, nowISO(),
	)
	return SendMessageResponse{OK: true}
}

func (b *Broker) pollMessages(req PollMessagesRequest) PollMessagesResponse {
	rows, err := b.db.Query(
		"SELECT id, from_id, to_id, text, sent_at FROM messages WHERE to_id = ? AND delivered = 0 ORDER BY sent_at ASC",
		req.ID,
	)
	if err != nil {
		return PollMessagesResponse{Messages: []Message{}}
	}
	defer rows.Close()

	var msgs []Message
	for rows.Next() {
		var m Message
		rows.Scan(&m.ID, &m.FromID, &m.ToID, &m.Text, &m.SentAt)
		msgs = append(msgs, m)
	}

	for _, m := range msgs {
		b.db.Exec("UPDATE messages SET delivered = 1 WHERE id = ?", m.ID)
	}

	if msgs == nil {
		msgs = []Message{}
	}
	return PollMessagesResponse{Messages: msgs}
}

func (b *Broker) unregister(req UnregisterRequest) {
	b.db.Exec("DELETE FROM peers WHERE id = ?", req.ID)
}

func (b *Broker) peerCount() int {
	var count int
	b.db.QueryRow("SELECT COUNT(*) FROM peers").Scan(&count)
	return count
}

func decodeBody[T any](r *http.Request) (T, error) {
	var v T
	err := json.NewDecoder(r.Body).Decode(&v)
	return v, err
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func runBroker(ctx context.Context) error {
	b, err := newBroker()
	if err != nil {
		return fmt.Errorf("init broker: %w", err)
	}
	defer b.db.Close()

	// Periodic stale cleanup
	var wg sync.WaitGroup
	wg.Go(func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b.cleanStalePeers()
			}
		}
	})

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, HealthResponse{Status: "ok", Peers: b.peerCount()})
	})

	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBody[RegisterRequest](r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, b.register(req))
	})

	mux.HandleFunc("POST /heartbeat", func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBody[HeartbeatRequest](r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		b.heartbeat(req)
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("POST /set-summary", func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBody[SetSummaryRequest](r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		b.setSummary(req)
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("POST /list-peers", func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBody[ListPeersRequest](r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, b.listPeers(req))
	})

	mux.HandleFunc("POST /send-message", func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBody[SendMessageRequest](r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, b.sendMessage(req))
	})

	mux.HandleFunc("POST /poll-messages", func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBody[PollMessagesRequest](r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, b.pollMessages(req))
	})

	mux.HandleFunc("POST /unregister", func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBody[UnregisterRequest](r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		b.unregister(req)
		writeJSON(w, map[string]bool{"ok": true})
	})

	port := brokerPort()
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	srv := &http.Server{Handler: mux}

	log.Printf("[claude-peers broker] listening on 127.0.0.1:%s (db: %s)", port, brokerDBPath())

	context.AfterFunc(ctx, func() {
		srv.Shutdown(context.Background())
	})

	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return err
	}

	wg.Wait()
	return nil
}
