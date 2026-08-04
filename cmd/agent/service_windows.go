//go:build windows

package main

import (
	"log"

	"golang.org/x/sys/windows/svc"
)

// A real Windows service for the machine-wide install.
//
// A scheduled task was the stand-in, and it showed: no service-control
// handler means the machine reports the agent as "a task", nothing restarts
// it on the terms a service manager offers, and stopping it cleanly is not
// something the operating system knows how to ask for. The task remains the
// right answer for a *user* install, which cannot create services at all.
//
// svc.IsWindowsService decides which mode this is, so the same binary serves
// both and nothing has to be passed in to tell it apart.

type agentService struct{ run func() }

func (s *agentService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}
	go s.run()
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		default:
			log.Printf("unexpected service control request %d", c.Cmd)
		}
	}
	return false, 0
}

// runAsServiceIfNeeded reports whether this process was started by the service
// control manager, and if so runs under it. The agent has no state worth
// flushing, so a stop is simply an exit.
func runAsServiceIfNeeded(run func()) bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("could not tell whether this is a service: %v", err)
		return false
	}
	if !isService {
		return false
	}
	log.Print("running as a Windows service")
	if err := svc.Run("multissh-agent", &agentService{run: run}); err != nil {
		log.Fatalf("service: %v", err)
	}
	return true
}
