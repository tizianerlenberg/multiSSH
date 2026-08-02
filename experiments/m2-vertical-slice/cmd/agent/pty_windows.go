//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"

	"github.com/UserExistsError/conpty"
	"golang.org/x/sys/windows"
)

// windowsShell is a shell attached to a ConPTY pseudo-console. ConPTY needs
// Windows 10 1809 / Server 2019 or newer. Nothing earlier can give a real
// terminal, so we refuse with a clear message rather than serve a degraded
// line-at-a-time shell that would break vim, Ctrl-C and tab completion.
type windowsShell struct {
	pty *conpty.ConPty
	pid int
}

func startShell(command, term string, cols, rows uint16) (ptyProcess, error) {
	if !conpty.IsConPtyAvailable() {
		return nil, errors.New("ConPTY unavailable: needs Windows 10 1809 / Server 2019 or newer")
	}

	p, err := conpty.Start(
		shellCommandLine(command),
		conpty.ConPtyDimensions(int(cols), int(rows)),
		conpty.ConPtyEnv(append(os.Environ(), "TERM="+term)),
	)
	if err != nil {
		return nil, err
	}
	return &windowsShell{pty: p, pid: p.Pid()}, nil
}

// shellCommandLine builds a command line, since Windows takes one string
// rather than an argv. PowerShell is preferred, with cmd.exe as the fallback
// for stripped-down installs.
func shellCommandLine(command string) string {
	if _, err := exec.LookPath("powershell.exe"); err == nil {
		if command == "" {
			return "powershell.exe -NoLogo"
		}
		return "powershell.exe -NoLogo -Command " + command
	}
	if command == "" {
		return "cmd.exe"
	}
	return "cmd.exe /C " + command
}

func (s *windowsShell) Read(p []byte) (int, error)  { return s.pty.Read(p) }
func (s *windowsShell) Write(p []byte) (int, error) { return s.pty.Write(p) }

func (s *windowsShell) Resize(cols, rows uint16) error {
	return s.pty.Resize(int(cols), int(rows))
}

func (s *windowsShell) Wait() (uint32, error) {
	return s.pty.Wait(context.Background())
}

// Terminate closes the pseudo-console and then kills the shell if it outlived
// it. Windows has no process group to signal, so processes the shell started
// itself are not reaped; a Job Object would be the thorough fix. In practice
// this is the same gap as backgrounded jobs on Unix.
func (s *windowsShell) Terminate() {
	s.pty.Close()
	if s.pid <= 0 {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(s.pid))
	if err != nil {
		return // already gone
	}
	defer windows.CloseHandle(h)
	windows.TerminateProcess(h, 1)
}
