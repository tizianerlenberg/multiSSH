//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
	"time"
)

type unixShell struct {
	f   *os.File
	cmd *exec.Cmd
}

// startShell runs an interactive shell, or a single command when one is given.
func startShell(command, term string, cols, rows uint16) (ptyProcess, error) {
	args := []string{shellPath()}
	if command != "" {
		args = append(args, "-c", command)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "TERM="+term)

	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		return nil, err
	}
	return &unixShell{f: f, cmd: cmd}, nil
}

func (s *unixShell) Read(p []byte) (int, error)  { return s.f.Read(p) }
func (s *unixShell) Write(p []byte) (int, error) { return s.f.Write(p) }

func (s *unixShell) Resize(cols, rows uint16) error {
	return pty.Setsize(s.f, &pty.Winsize{Rows: rows, Cols: cols})
}

func (s *unixShell) Wait() (uint32, error) {
	err := s.cmd.Wait()
	if ee, ok := err.(*exec.ExitError); ok {
		return uint32(ee.ExitCode()), nil
	}
	return 0, err
}

// Terminate hangs up the terminal and signals the shell's entire process group.
// Closing the pty alone is not enough: removing the group signal was measured
// to leave a foreground process running after an abrupt disconnect. Jobs
// backgrounded with & get their own process group and survive, exactly as they
// do under a normal sshd.
func (s *unixShell) Terminate() {
	s.f.Close()
	if s.cmd.Process != nil {
		syscall.Kill(-s.cmd.Process.Pid, syscall.SIGHUP)
	}
}

func shellPath() string {
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	for _, c := range []string{"/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "/bin/sh"
}

// outputDrainTimeout bounds the wait for a finished command's output to reach
// the client. A pseudo-terminal here reports EOF once the child has gone and
// its output has been read, so the wait normally ends immediately and this is
// only reached when something the shell left behind still holds the terminal
// open.
const outputDrainTimeout = 5 * time.Second
