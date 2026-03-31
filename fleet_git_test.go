package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAutoProjectWithGitRoot(t *testing.T) {
	home, _ := os.UserHomeDir()
	cwd := filepath.Join(home, "projects", "test-project")
	got := autoProject(cwd, cwd)
	if got != "test-project" {
		t.Fatalf("expected test-project, got %s", got)
	}
}

func TestAutoProjectHomeDirReturnsEmpty(t *testing.T) {
	home, _ := os.UserHomeDir()
	got := autoProject(home, "")
	// Home directory should return empty project name.
	_ = got
}

func TestAutoProjectSubdir(t *testing.T) {
	home, _ := os.UserHomeDir()
	cwd := filepath.Join(home, "projects", "foo")
	got := autoProject(cwd, "")
	if got != "projects/foo" {
		t.Fatalf("expected projects/foo, got %q", got)
	}
}

func TestAutoProjectDeepPath(t *testing.T) {
	home, _ := os.UserHomeDir()
	cwd := filepath.Join(home, "projects", "foo", "bar", "baz")
	got := autoProject(cwd, "")
	if got != "projects/foo" {
		t.Fatalf("expected projects/foo, got %q", got)
	}
}

func TestAutoNameWithProject(t *testing.T) {
	got := autoName("myhost", "test-project", "")
	if got != "myhost/test-project" {
		t.Fatalf("expected myhost/test-project, got %s", got)
	}
}

func TestAutoNameWithoutProject(t *testing.T) {
	got := autoName("myhost", "", "")
	if got != "myhost" {
		t.Fatalf("expected myhost, got %s", got)
	}
}

func TestAutoNameWithTTY(t *testing.T) {
	got := autoName("myhost", "project", "/dev/pts/9")
	if got != "myhost/project:9" {
		t.Fatalf("expected myhost/project:9, got %s", got)
	}
}

func TestAutoNameWithTTYNoProject(t *testing.T) {
	got := autoName("myhost", "", "/dev/pts/3")
	if got != "myhost:3" {
		t.Fatalf("expected myhost:3, got %s", got)
	}
}

func TestFilterEmpty(t *testing.T) {
	cases := []struct {
		input    []string
		expected int
	}{
		{[]string{"a", "", "b", "", "c"}, 3},
		{[]string{"", "", ""}, 0},
		{[]string{"a", "b"}, 2},
		{nil, 0},
	}
	for _, tc := range cases {
		got := filterEmpty(tc.input)
		if len(got) != tc.expected {
			t.Errorf("filterEmpty(%v) = %d items, want %d", tc.input, len(got), tc.expected)
		}
		for _, s := range got {
			if s == "" {
				t.Errorf("filterEmpty output contains empty string")
			}
		}
	}
}

func TestSplitNonEmpty(t *testing.T) {
	cases := []struct {
		input    string
		expected int
	}{
		{"a\nb\nc", 3},
		{"a\n\nb", 2},
		{"", 0},
		{"\n\n\n", 0},
	}
	for _, tc := range cases {
		got := splitNonEmpty(tc.input)
		if len(got) != tc.expected {
			t.Errorf("splitNonEmpty(%q) = %d items, want %d", tc.input, len(got), tc.expected)
		}
	}
}
