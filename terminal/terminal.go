package terminal

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aymanbagabas/go-pty"
	"github.com/google/uuid"
)

const (
	MaxWriteBytes = 64 * 1024 // 64 KiB cap for PTY stdin writes
	MinCols       = 2
	MaxCols       = 1024
	MinRows       = 1
	MaxRows       = 512
)

// EventEmitter is a callback invoked whenever a terminal session emits output or exits.
type EventEmitter func(eventName string, data any)

type ptySession struct {
	id     string
	shell  string
	cwd    string
	ptm    pty.Pty
	cmd    *pty.Cmd
	closed atomic.Bool
}

// Manager manages concurrent PTY sessions across MyTerm, Heapi, and byCode.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*ptySession
	emit     EventEmitter
}

// NewManager creates a new cross-platform PTY session manager.
func NewManager(emitter EventEmitter) *Manager {
	return &Manager{
		sessions: make(map[string]*ptySession),
		emit:     emitter,
	}
}

// SetEmitter sets or updates the event emitter callback.
func (m *Manager) SetEmitter(emitter EventEmitter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.emit = emitter
}

func (m *Manager) emitEvent(name string, data any) {
	m.mu.RLock()
	emit := m.emit
	m.mu.RUnlock()
	if emit != nil {
		emit(name, data)
	}
}

// CreateSession starts a new PTY session with an auto-generated UUID and returns its ID.
func (m *Manager) CreateSession(shell, cwd string, cols, rows int) (string, error) {
	id := uuid.New().String()
	if err := m.StartSession(id, shell, cwd, cols, rows); err != nil {
		return "", err
	}
	return id, nil
}

// StartSession starts a PTY session with an explicit session ID.
func (m *Manager) StartSession(sessionID, shell, cwd string, cols, rows int) error {
	if !IsAllowedShell(shell) {
		return fmt.Errorf("rejected unknown shell %q", shell)
	}
	if shell == "" {
		shell = BestShell()
	}

	m.mu.Lock()
	if old, exists := m.sessions[sessionID]; exists {
		old.closed.Store(true)
		_ = old.ptm.Close()
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()

	ptm, err := pty.New()
	if err != nil {
		return fmt.Errorf("pty.New: %w", err)
	}

	cols = clamp(cols, MinCols, MaxCols, 100)
	rows = clamp(rows, MinRows, MaxRows, 30)
	_ = ptm.Resize(cols, rows)

	args := ShellArgs(shell)
	if absShell, err := exec.LookPath(shell); err == nil {
		shell = absShell
	}

	cmd := ptm.Command(shell, args...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")

	resolvedCwd := resolveCwd(cwd)
	if resolvedCwd != "" {
		cmd.Dir = resolvedCwd
	}

	if err := cmd.Start(); err != nil {
		_ = ptm.Close()
		return fmt.Errorf("cmd.Start (%s): %w", shell, err)
	}

	sess := &ptySession{
		id:    sessionID,
		shell: shell,
		cwd:   resolvedCwd,
		ptm:   ptm,
		cmd:   cmd,
	}

	m.mu.Lock()
	m.sessions[sessionID] = sess
	m.mu.Unlock()

	go func() {
		buf := make([]byte, 32768)
		for {
			n, readErr := ptm.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				// Emit both scoped event (MyTerm/byCode style) and payload map (Heapi style)
				m.emitEvent("terminal-output:"+sessionID, chunk)
				m.emitEvent("terminal:data", map[string]string{
					"sessionID": sessionID,
					"data":      chunk,
				})
			}
			if readErr != nil {
				if !sess.closed.Load() {
					exitMsg := ""
					if readErr != io.EOF {
						exitMsg = readErr.Error()
					}
					m.emitEvent("terminal-exit:"+sessionID, exitMsg)
					m.emitEvent("terminal:exit", map[string]string{
						"sessionID": sessionID,
						"error":     exitMsg,
					})
				}
				m.mu.Lock()
				delete(m.sessions, sessionID)
				m.mu.Unlock()
				return
			}
		}
	}()

	return nil
}

// Write sends input keystrokes to the PTY session.
func (m *Manager) Write(sessionID, data string) error {
	if len(data) > MaxWriteBytes {
		return fmt.Errorf("payload too large (%d bytes, max %d)", len(data), MaxWriteBytes)
	}
	m.mu.RLock()
	sess, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session %s not found", sessionID)
	}
	_, err := sess.ptm.Write([]byte(data))
	return err
}

// Resize updates the dimensions of the PTY session.
func (m *Manager) Resize(sessionID string, cols, rows int) error {
	cols = clamp(cols, MinCols, MaxCols, 80)
	rows = clamp(rows, MinRows, MaxRows, 24)
	m.mu.RLock()
	sess, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return nil
	}
	return sess.ptm.Resize(cols, rows)
}

// CloseSession closes a specific PTY session.
func (m *Manager) CloseSession(sessionID string) error {
	m.mu.Lock()
	sess, ok := m.sessions[sessionID]
	if ok {
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	sess.closed.Store(true)
	err := sess.ptm.Close()
	m.emitEvent("terminal-exit:"+sessionID, "")
	return err
}

// CloseAll terminates all active PTY sessions.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	all := make([]*ptySession, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.sessions = make(map[string]*ptySession)
	m.mu.Unlock()

	for _, s := range all {
		s.closed.Store(true)
		_ = s.ptm.Close()
	}
}

// Count returns the number of active PTY sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func clamp(val, minVal, maxVal, fallback int) int {
	if val <= 0 {
		return fallback
	}
	if val < minVal {
		return minVal
	}
	if val > maxVal {
		return maxVal
	}
	return val
}

func resolveCwd(cwd string) string {
	cwd = strings.TrimSpace(cwd)
	if strings.HasPrefix(cwd, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			if cwd == "~" {
				return home
			}
			if len(cwd) > 1 && (cwd[1] == '/' || cwd[1] == '\\') {
				return filepath.Join(home, cwd[2:])
			}
		}
	}
	if cwd == "" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	return cwd
}
