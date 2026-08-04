//go:build windows

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"unsafe"

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
	// job holds the shell and everything it starts. Windows has no process
	// group to signal, so without this only the shell itself was killed when a
	// session ended and anything it had started was orphaned -- left running
	// forever on a machine nobody is sitting at. Closing the job handle kills
	// the whole tree.
	job windows.Handle
}

// newKillOnCloseJob creates a job object whose members die when the last
// handle to it closes. That is the property that makes it a reliable teardown:
// it holds even if this process is killed rather than exiting cleanly.
func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	_, err = windows.SetInformationJobObject(job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
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

	s := &windowsShell{pty: p, pid: p.Pid()}

	// Best effort. A shell that cannot be put in a job still works; it just
	// leaves its children behind on disconnect, which is what always happened
	// before. Refusing to open a session over it would be the worse trade for
	// a tool whose job is getting you in.
	if job, err := newKillOnCloseJob(); err != nil {
		log.Printf("no job object, so processes this session starts will outlive it: %v", err)
	} else if h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(s.pid)); err != nil {
		log.Printf("could not open the shell to place it in a job: %v", err)
		windows.CloseHandle(job)
	} else {
		if err := windows.AssignProcessToJobObject(job, h); err != nil {
			log.Printf("could not place the shell in a job: %v", err)
			windows.CloseHandle(job)
		} else {
			s.job = job
		}
		windows.CloseHandle(h)
	}
	return s, nil
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

// Terminate closes the pseudo-console, then the job, which kills the shell and
// everything it started. The explicit TerminateProcess is a fallback for the
// case where the job could not be created at all.
func (s *windowsShell) Terminate() {
	s.pty.Close()

	if s.job != 0 {
		// KILL_ON_JOB_CLOSE means this is the kill.
		windows.CloseHandle(s.job)
		s.job = 0
		return
	}

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
