//go:build !windows

package main

// runAsServiceIfNeeded is Windows-only. Everywhere else the agent is started
// by systemd or launchd, which need nothing from the process beyond its
// staying alive.
func runAsServiceIfNeeded(func()) bool { return false }
