package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	pollInterval      = 1 * time.Second
	heartbeatInterval = 15 * time.Second
)

func brokerURL() string {
	return "http://127.0.0.1:" + brokerPort()
}

func brokerFetch(path string, body any, result any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(brokerURL()+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("broker %s: %d %s", path, resp.StatusCode, string(b))
	}
	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

func isBrokerAlive() bool {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(brokerURL() + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func ensureBroker() error {
	if isBrokerAlive() {
		logMCP("Broker already running")
		return nil
	}

	logMCP("Starting broker daemon...")
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := exec.Command(exe, "broker")
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start broker: %w", err)
	}
	// Detach -- don't wait
	go cmd.Wait()

	for range 30 {
		time.Sleep(200 * time.Millisecond)
		if isBrokerAlive() {
			logMCP("Broker started")
			return nil
		}
	}
	return fmt.Errorf("broker failed to start after 6s")
}

func runServer(ctx context.Context) error {
	if err := ensureBroker(); err != nil {
		return err
	}

	cwd, _ := os.Getwd()
	root := gitRoot(cwd)
	tty := getTTY()
	branch := gitBranch(cwd)
	files := recentFiles(cwd, 10)

	logMCP("CWD: %s", cwd)
	logMCP("Git root: %s", root)
	logMCP("TTY: %s", tty)

	// Generate summary async (best-effort, 3s deadline)
	summaryCh := make(chan string, 1)
	go func() {
		summaryCh <- generateSummary(cwd, root, branch, files)
	}()

	var initialSummary string
	select {
	case s := <-summaryCh:
		initialSummary = s
		if s != "" {
			logMCP("Auto-summary: %s", s)
		}
	case <-time.After(3 * time.Second):
		logMCP("Auto-summary timed out (non-blocking)")
	}

	// Register with broker
	var reg RegisterResponse
	if err := brokerFetch("/register", RegisterRequest{
		PID:     os.Getpid(),
		CWD:     cwd,
		GitRoot: root,
		TTY:     tty,
		Summary: initialSummary,
	}, &reg); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	myID := reg.ID
	logMCP("Registered as peer %s", myID)

	// If summary was slow, apply it late
	if initialSummary == "" {
		go func() {
			if s := <-summaryCh; s != "" {
				brokerFetch("/set-summary", SetSummaryRequest{ID: myID, Summary: s}, nil)
				logMCP("Late auto-summary applied: %s", s)
			}
		}()
	}

	t := newMCPTransport()

	// Cleanup on exit
	defer func() {
		brokerFetch("/unregister", UnregisterRequest{ID: myID}, nil)
		logMCP("Unregistered from broker")
	}()

	// Poll loop: check for inbound messages and push as channel notifications
	var wg sync.WaitGroup
	pollCtx, pollCancel := context.WithCancel(ctx)
	defer pollCancel()

	wg.Go(func() {
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
				pollAndPush(myID, cwd, root, t)
			}
		}
	})

	// Heartbeat loop
	wg.Go(func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
				brokerFetch("/heartbeat", HeartbeatRequest{ID: myID}, nil)
			}
		}
	})

	// Main loop: read and handle MCP requests from stdin
	for {
		req, err := t.readRequest()
		if err != nil {
			if err == io.EOF {
				break
			}
			logMCP("Read error: %v", err)
			break
		}

		switch req.Method {
		case "initialize":
			handleInitialize(req.ID, t)

		case "notifications/initialized":
			// Client ack, nothing to do

		case "tools/list":
			handleToolsList(req.ID, t)

		case "tools/call":
			handleToolCall(req.ID, req.Params, myID, cwd, root, t)

		default:
			if req.ID != nil {
				t.respondError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
			}
		}
	}

	pollCancel()
	wg.Wait()
	return nil
}

func handleToolCall(id any, params json.RawMessage, myID, cwd, root string, t *MCPTransport) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	json.Unmarshal(params, &call)

	switch call.Name {
	case "list_peers":
		var args struct {
			Scope string `json:"scope"`
		}
		json.Unmarshal(call.Arguments, &args)

		var peers []Peer
		err := brokerFetch("/list-peers", ListPeersRequest{
			Scope:     args.Scope,
			CWD:       cwd,
			GitRoot:   root,
			ExcludeID: myID,
		}, &peers)
		if err != nil {
			toolError(id, t, "Error listing peers: %v", err)
			return
		}

		if len(peers) == 0 {
			toolResult(id, t, "No other Claude Code instances found (scope: %s).", args.Scope)
			return
		}

		var sb strings.Builder
		fmt.Fprintf(&sb, "Found %d peer(s) (scope: %s):\n\n", len(peers), args.Scope)
		for _, p := range peers {
			fmt.Fprintf(&sb, "ID: %s\n  PID: %d\n  CWD: %s\n", p.ID, p.PID, p.CWD)
			if p.GitRoot != "" {
				fmt.Fprintf(&sb, "  Repo: %s\n", p.GitRoot)
			}
			if p.TTY != "" {
				fmt.Fprintf(&sb, "  TTY: %s\n", p.TTY)
			}
			if p.Summary != "" {
				fmt.Fprintf(&sb, "  Summary: %s\n", p.Summary)
			}
			fmt.Fprintf(&sb, "  Last seen: %s\n\n", p.LastSeen)
		}
		toolResult(id, t, "%s", sb.String())

	case "send_message":
		var args struct {
			ToID    string `json:"to_id"`
			Message string `json:"message"`
		}
		json.Unmarshal(call.Arguments, &args)

		var resp SendMessageResponse
		err := brokerFetch("/send-message", SendMessageRequest{
			FromID: myID,
			ToID:   args.ToID,
			Text:   args.Message,
		}, &resp)
		if err != nil {
			toolError(id, t, "Error sending message: %v", err)
			return
		}
		if !resp.OK {
			toolError(id, t, "Failed to send: %s", resp.Error)
			return
		}
		toolResult(id, t, "Message sent to peer %s", args.ToID)

	case "set_summary":
		var args struct {
			Summary string `json:"summary"`
		}
		json.Unmarshal(call.Arguments, &args)

		err := brokerFetch("/set-summary", SetSummaryRequest{
			ID:      myID,
			Summary: args.Summary,
		}, nil)
		if err != nil {
			toolError(id, t, "Error setting summary: %v", err)
			return
		}
		toolResult(id, t, "Summary updated: %q", args.Summary)

	case "check_messages":
		var resp PollMessagesResponse
		err := brokerFetch("/poll-messages", PollMessagesRequest{ID: myID}, &resp)
		if err != nil {
			toolError(id, t, "Error checking messages: %v", err)
			return
		}
		if len(resp.Messages) == 0 {
			toolResult(id, t, "No new messages.")
			return
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "%d new message(s):\n\n", len(resp.Messages))
		for _, m := range resp.Messages {
			fmt.Fprintf(&sb, "From %s (%s):\n%s\n\n---\n\n", m.FromID, m.SentAt, m.Text)
		}
		toolResult(id, t, "%s", sb.String())

	default:
		t.respondError(id, -32601, fmt.Sprintf("Unknown tool: %s", call.Name))
	}
}

func toolResult(id any, t *MCPTransport, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	t.respond(id, map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
	})
}

func toolError(id any, t *MCPTransport, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	t.respond(id, map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
		"isError": true,
	})
}

func pollAndPush(myID, cwd, root string, t *MCPTransport) {
	var resp PollMessagesResponse
	if err := brokerFetch("/poll-messages", PollMessagesRequest{ID: myID}, &resp); err != nil {
		return
	}

	for _, msg := range resp.Messages {
		// Look up sender info
		fromSummary, fromCwd := "", ""
		var peers []Peer
		if err := brokerFetch("/list-peers", ListPeersRequest{
			Scope:   "machine",
			CWD:     cwd,
			GitRoot: root,
		}, &peers); err == nil {
			for _, p := range peers {
				if p.ID == msg.FromID {
					fromSummary = p.Summary
					fromCwd = p.CWD
					break
				}
			}
		}

		t.writeNotification("notifications/claude/channel", map[string]any{
			"content": msg.Text,
			"meta": map[string]any{
				"from_id":      msg.FromID,
				"from_summary": fromSummary,
				"from_cwd":     fromCwd,
				"sent_at":      msg.SentAt,
			},
		})

		logMCP("Pushed message from %s: %.80s", msg.FromID, msg.Text)
	}
}
