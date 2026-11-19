// Package browser opens the sign-in pages of opkssh and Pomerium without
// taking the keyboard focus away from the terminal, where the platform allows
// it:
//   - macOS: `open -g` opens the page without bringing the browser forward;
//   - Linux on Hyprland (hyprctl) or X11 (xdotool): the page opens with the
//     default browser, then the previously focused window gets the focus back;
//   - elsewhere (Windows, other Wayland desktops): the default browser opens
//     the page and the system decides about focus.
//
// A custom command can replace all of this: set `browser:` in the ocd config
// or OCD_BROWSER. "{url}" in the command is replaced by the page address
// (otherwise the address is appended); "none" only prints the address.
package browser

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/skratchdot/open-golang/open"
)

// EnvCommand overrides the configured browser command.
const EnvCommand = "OCD_BROWSER"

// HelperEnv marks an ocd process started by the Pomerium tunnel as its
// browser command (it runs `<browser command> <url>` and ocd passes itself).
const HelperEnv = "OCD_BROWSER_HELPER"

// Opener opens sign-in pages.
type Opener struct {
	// Command is the configured browser command; empty means the default.
	Command string
	// KeepFocus is how long to watch for a focus change and undo it.
	KeepFocus time.Duration
}

// New returns an Opener using OCD_BROWSER, else the configured command.
func New(configured string) Opener {
	c := configured
	if v, ok := os.LookupEnv(EnvCommand); ok {
		c = v
	}
	return Opener{Command: strings.TrimSpace(c), KeepFocus: 3 * time.Second}
}

// Disabled reports whether pages must only be printed.
func (o Opener) Disabled() bool { return o.Command == "none" }

// CommandArgs expands a custom command template for url.
func CommandArgs(command, url string) []string {
	fields := strings.Fields(command)
	replaced := false
	for i, f := range fields {
		if strings.Contains(f, "{url}") {
			fields[i] = strings.ReplaceAll(f, "{url}", url)
			replaced = true
		}
	}
	if !replaced {
		fields = append(fields, url)
	}
	return fields
}

// Open opens url.
func (o Opener) Open(url string) error {
	if o.Disabled() {
		return nil
	}
	if o.Command != "" {
		args := CommandArgs(o.Command, url)
		return exec.Command(args[0], args[1:]...).Start()
	}
	if runtime.GOOS == "darwin" {
		return exec.Command("open", "-g", url).Run()
	}
	if f := focusKeeper(); f != nil {
		prev := f.active()
		if err := open.Start(url); err != nil {
			return err
		}
		if prev != "" {
			f.restore(prev, o.KeepFocus)
		}
		return nil
	}
	return open.Start(url)
}

type focus struct {
	active func() string
	focus  func(string)
}

// restore gives the focus back to prev whenever another window takes it
// during d, and returns once prev has kept it for half a second.
func (f focus) restore(prev string, d time.Duration) {
	deadline := time.Now().Add(d)
	var restoredAt time.Time
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		cur := f.active()
		if cur != "" && cur != prev {
			f.focus(prev)
			restoredAt = time.Now()
			continue
		}
		if !restoredAt.IsZero() && time.Since(restoredAt) > 500*time.Millisecond {
			return
		}
	}
}

func focusKeeper() *focus {
	if runtime.GOOS != "linux" {
		return nil
	}
	if os.Getenv("HYPRLAND_INSTANCE_SIGNATURE") != "" {
		if _, err := exec.LookPath("hyprctl"); err == nil {
			return &focus{active: hyprActive, focus: func(a string) {
				_ = exec.Command("hyprctl", "dispatch", "focuswindow", "address:"+a).Run()
			}}
		}
	}
	if os.Getenv("DISPLAY") != "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		if _, err := exec.LookPath("xdotool"); err == nil {
			return &focus{active: x11Active, focus: func(id string) {
				_ = exec.Command("xdotool", "windowactivate", id).Run()
			}}
		}
	}
	return nil
}

func hyprActive() string {
	out, err := exec.Command("hyprctl", "activewindow", "-j").Output()
	if err != nil {
		return ""
	}
	return parseHyprActive(out)
}

func parseHyprActive(out []byte) string {
	var w struct {
		Address string `json:"address"`
	}
	if json.Unmarshal(out, &w) != nil {
		return ""
	}
	return w.Address
}

func x11Active() string {
	out, err := exec.Command("xdotool", "getactivewindow").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// HelperMain handles `ocd <url>` started by the Pomerium tunnel as its
// browser command. It returns false when args are not such a call.
//
// The call is only acknowledged. pomerium-cli abandons the gateway sign-in
// when its browser command fails, and this process has no terminal to print
// to, so the ocd process that owns the tunnel opens the page, or prints its
// address when no browser can be opened (headless Linux, WSL without a
// browser opener, OCD_BROWSER=none). Opening it here too would open two tabs.
func HelperMain(args []string, _ string) (bool, error) {
	if os.Getenv(HelperEnv) != "1" || len(args) != 1 ||
		!(strings.HasPrefix(args[0], "https://") || strings.HasPrefix(args[0], "http://")) {
		return false, nil
	}
	return true, nil
}
