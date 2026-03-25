package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	switch os.Args[1] {
	case "broker":
		if err := runBroker(ctx); err != nil {
			log.Fatal(err)
		}
	case "server":
		if err := runServer(ctx); err != nil {
			log.Fatal(err)
		}
	case "status":
		cliStatus()
	case "peers":
		cliPeers()
	case "send":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: claude-peers send <peer-id> <message>")
			os.Exit(1)
		}
		cliSend(os.Args[2], strings.Join(os.Args[3:], " "))
	case "kill-broker":
		cliKillBroker()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`claude-peers - peer discovery and messaging for Claude Code

Usage:
  claude-peers broker        Start the broker daemon
  claude-peers server        Start MCP stdio server (used by Claude Code)
  claude-peers status        Show broker status and all peers
  claude-peers peers         List all peers
  claude-peers send <id> <msg>  Send a message to a peer
  claude-peers kill-broker   Stop the broker daemon`)
}

func cliFetch(path string, body any, result any) error {
	url := "http://127.0.0.1:" + brokerPort()
	data, _ := json.Marshal(body)
	client := http.Client{Timeout: 3 * time.Second}

	var resp *http.Response
	var err error
	if body != nil {
		resp, err = client.Post(url+path, "application/json", bytes.NewReader(data))
	} else {
		resp, err = client.Get(url + path)
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%d: %s", resp.StatusCode, string(b))
	}
	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

func cliStatus() {
	var health HealthResponse
	if err := cliFetch("/health", nil, &health); err != nil {
		fmt.Println("Broker is not running.")
		return
	}
	fmt.Printf("Broker: %s (%d peer(s) registered)\n", health.Status, health.Peers)
	fmt.Printf("URL: %s\n", "http://127.0.0.1:"+brokerPort())

	if health.Peers > 0 {
		var peers []Peer
		cliFetch("/list-peers", ListPeersRequest{Scope: "machine", CWD: "/"}, &peers)
		fmt.Println("\nPeers:")
		for _, p := range peers {
			fmt.Printf("  %s  PID:%d  %s\n", p.ID, p.PID, p.CWD)
			if p.Summary != "" {
				fmt.Printf("         %s\n", p.Summary)
			}
			if p.TTY != "" {
				fmt.Printf("         TTY: %s\n", p.TTY)
			}
			fmt.Printf("         Last seen: %s\n", p.LastSeen)
		}
	}
}

func cliPeers() {
	var peers []Peer
	if err := cliFetch("/list-peers", ListPeersRequest{Scope: "machine", CWD: "/"}, &peers); err != nil {
		fmt.Println("Broker is not running.")
		return
	}
	if len(peers) == 0 {
		fmt.Println("No peers registered.")
		return
	}
	for _, p := range peers {
		fmt.Printf("%s  PID:%d  %s\n", p.ID, p.PID, p.CWD)
		if p.Summary != "" {
			fmt.Printf("  Summary: %s\n", p.Summary)
		}
	}
}

func cliSend(toID, msg string) {
	var resp SendMessageResponse
	if err := cliFetch("/send-message", SendMessageRequest{
		FromID: "cli",
		ToID:   toID,
		Text:   msg,
	}, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if resp.OK {
		fmt.Printf("Message sent to %s\n", toID)
	} else {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", resp.Error)
		os.Exit(1)
	}
}

func cliKillBroker() {
	var health HealthResponse
	if err := cliFetch("/health", nil, &health); err != nil {
		fmt.Println("Broker is not running.")
		return
	}
	fmt.Printf("Broker has %d peer(s). Shutting down...\n", health.Peers)

	// Find and kill the process on the broker port
	out, err := execOutput("lsof", "-ti", ":"+brokerPort())
	if err != nil {
		fmt.Println("Could not find broker process.")
		return
	}
	for pid := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if pid != "" {
			execOutput("kill", pid)
		}
	}
	fmt.Println("Broker stopped.")
}

func execOutput(name string, args ...string) (string, error) {
	var buf bytes.Buffer
	cmd := execCommand(name, args...)
	cmd.Stdout = &buf
	err := cmd.Run()
	return buf.String(), err
}

func execCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}
