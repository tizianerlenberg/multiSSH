//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"

	"github.com/UserExistsError/conpty"
	"golang.org/x/sys/windows"
	"time"
)

// windowsShell is a shell attached to a ConPTY pseudo-console. ConPTY needs
// Windows 10 1809 / Server 2019 or newer. Nothing earlier can give a real
// terminal, so we refuse with a clear message rather than serve a degraded
// line-at-a-time shell that would break vim, Ctrl-C and tab completion.
type windowsShell struct {
	pty *conpty.ConPty
	pid int
}

// A job object would kill the shell and everything it started when a session
// ends, which Windows otherwise cannot do -- there is no process group to
// signal, so children are orphaned. It was tried and had to come out.
//
// The agent updates itself over its own tunnel: the update runs in a session,
// and its last act is to restart the agent. With the shell in a job that dies
// with the session, stopping the agent killed the update script halfway
// through -- after the binary was swapped and before anything was started
// again -- and left the machine with an agent that was installed, registered,
// and not running. Losing a few orphaned processes is a far smaller problem
// than losing the machine.
//
// The way back to it is to take the restart out of the session entirely: a
// one-shot scheduled task, owned by Task Scheduler rather than by the job, so
// that nothing the session does can interrupt it. Then the job can return.

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

// Terminate closes the pseudo-console and kills the shell. Processes the shell
// started are left behind -- see the note above the type for why the job
// object that would have caught them had to be removed.
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

// outputDrainTimeout is short here on purpose.
//
// ConPTY does not close its output pipe when the child exits, so the read
// never reports EOF and this wait *always* runs to the end. At five seconds --
// the figure that suits a Unix pseudo-terminal, where EOF arrives promptly --
// every command and every logout on Windows took five seconds longer than it
// should, which is exactly what was reported.
//
// The bug the wait exists for is a scheduling race: the copying goroutine not
// having run even once before the channel is closed. A fraction of a second
// covers that with room to spare.
const outputDrainTimeout = 300 * time.Millisecond
