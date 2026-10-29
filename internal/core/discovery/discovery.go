// Package discovery distinguishes the execution environment from the device host.
package discovery

import (
	"context"
	"os"
	"runtime"
	"strings"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/platforms"
)

type facts struct {
	os, arch, version, release, cgroup string
	wsl, chrome, container, remote     bool
}

func detect(f facts) findings.Environment {
	e := findings.Environment{OS: f.os, HostOS: f.os, Architecture: f.arch, Type: "native", Remote: f.remote, OSVersion: f.version, Tools: []string{}, Limitations: []string{}}
	switch {
	case f.os == "linux" && (f.wsl || strings.Contains(strings.ToLower(f.version), "microsoft")):
		e.Type = "wsl"
		e.HostOS = "windows"
		e.Limitations = append(e.Limitations, "Linux subsystem only; native Windows is not inspected and /mnt drives are excluded by default.")
	case f.os == "linux" && f.chrome:
		e.Type = "crostini"
		e.HostOS = "chromeos"
		e.Limitations = append(e.Limitations, "Linux container and explicitly shared folders only; no ChromeOS host, Android apps or host startup/performance visibility.")
	case f.container || strings.Contains(f.cgroup, "docker") || strings.Contains(f.cgroup, "kubepods") || strings.Contains(f.cgroup, "containerd"):
		e.Type = "container"
		e.HostOS = "unknown"
		e.Limitations = append(e.Limitations, "Container namespace only; underlying host OS and host metrics are unknown.")
	}
	if f.remote {
		if e.Type == "native" {
			e.Type = "remote"
		}
		e.Limitations = append(e.Limitations, "SSH/remote execution detected; this environment may not be the device in front of the user.")
	}
	if f.os == "linux" {
		for _, line := range strings.Split(f.release, "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				e.OSVersion = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				break
			}
		}
	}
	return e
}
func Detect() findings.Environment {
	read := func(p string) string { b, _ := platforms.ReadSmall(p, 64<<10); return string(b) }
	exists := func(p string) bool { _, e := os.Stat(p); return e == nil }
	f := facts{os: runtime.GOOS, arch: runtime.GOARCH, version: "unknown", remote: os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != ""}
	if runtime.GOOS == "linux" {
		f.version = read("/proc/sys/kernel/osrelease")
		f.release = read("/etc/os-release")
		f.cgroup = read("/proc/1/cgroup")
		f.wsl = os.Getenv("WSL_INTEROP") != "" || os.Getenv("WSL_DISTRO_NAME") != ""
		f.chrome = exists("/dev/.cros_milestone") || strings.Contains(read("/run/host/os-release"), "Chrome OS") || exists("/mnt/chromeos") && exists("/dev/.cros_milestone")
		f.container = exists("/.dockerenv") || exists("/run/.containerenv") || os.Getenv("container") != "" || strings.TrimSpace(read("/run/systemd/container")) != ""
	}
	if runtime.GOOS == "darwin" {
		if b, e := platforms.Run(context.Background(), "sw_vers", "-productVersion"); e == nil {
			f.version = strings.TrimSpace(string(b))
		}
	}
	if runtime.GOOS == "windows" {
		if b, err := platforms.Run(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command", `[System.Environment]::OSVersion.Version.ToString()`); err == nil {
			f.version = strings.TrimSpace(string(b))
		}
	}
	e := detect(f)
	for _, name := range []string{"ps", "sysctl", "vm_stat", "dpkg-query", "rpm", "pacman", "flatpak", "snap", "systemctl", "powershell"} {
		if platforms.Tool(name) != "" {
			e.Tools = append(e.Tools, name)
		}
	}
	return e
}
