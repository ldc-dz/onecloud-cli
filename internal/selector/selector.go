// Package selector is a small arrow-key picker drawn on the controlling
// terminal (/dev/tty), so it works even when stdin or stdout is redirected.
// Without a terminal it fails with ErrNotInteractive instead of guessing;
// cancelling (Esc, q, Ctrl-C, Ctrl-D) returns ErrCanceled and leaves no
// trace: the menu is erased and the terminal mode restored.
package selector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrNotInteractive means there is no terminal to ask on. Callers should
// tell the user which argument or flag to pass instead.
var ErrNotInteractive = errors.New("no interactive terminal: pass the target explicitly")

// ErrCanceled means the user dismissed the selector.
var ErrCanceled = errors.New("selection canceled")

// ErrNoChoice means there is nothing selectable.
var ErrNoChoice = errors.New("nothing to select")

// Item is one row. Disabled rows are shown but cannot be chosen (for
// example an instance that is not ready yet).
type Item struct {
	Label    string
	Detail   string
	Disabled bool
}

// openTerminal opens the controlling terminal; tests replace it.
var openTerminal = openTTY

// Select asks on /dev/tty and returns the chosen index.
func Select(ctx context.Context, title string, items []Item) (int, error) {
	if firstEnabled(items) < 0 {
		return -1, ErrNoChoice
	}
	t, err := openTerminal()
	if err != nil {
		return -1, ErrNotInteractive
	}
	defer t.Close()
	return run(ctx, t.next, t, title, items)
}

// key is a decoded key press.
type key int

const (
	keyNone key = iota
	keyUp
	keyDown
	keyHome
	keyEnd
	keyEnter
	keyCancel
)

// nextByte returns one input byte; ok=false means a read timeout with no
// input (used to notice a lone Esc and context cancellation).
type nextByte func() (b byte, ok bool, err error)

func readKey(next nextByte) (key, bool, error) {
	b, ok, err := next()
	if err != nil || !ok {
		return keyNone, ok, err
	}
	switch b {
	case '\r', '\n':
		return keyEnter, true, nil
	case 3, 4, 'q': // Ctrl-C, Ctrl-D, q
		return keyCancel, true, nil
	case 'k', 16: // k, Ctrl-P
		return keyUp, true, nil
	case 'j', 14: // j, Ctrl-N
		return keyDown, true, nil
	case 0x1b:
		b2, ok, err := next()
		if err != nil {
			return keyNone, true, err
		}
		if !ok || (b2 != '[' && b2 != 'O') {
			return keyCancel, true, nil // lone Esc
		}
		b3, ok, err := next()
		if err != nil || !ok {
			return keyNone, true, err
		}
		switch b3 {
		case 'A':
			return keyUp, true, nil
		case 'B':
			return keyDown, true, nil
		case 'H':
			return keyHome, true, nil
		case 'F':
			return keyEnd, true, nil
		}
		// Drain the rest of longer sequences (e.g. ESC [ 1 ~) up to a final byte.
		for i := 0; i < 8 && ((b3 >= '0' && b3 <= '9') || b3 == ';'); i++ {
			if b3, ok, err = next(); err != nil || !ok {
				break
			}
		}
		return keyNone, true, err
	}
	return keyNone, true, nil
}

func firstEnabled(items []Item) int {
	for i, it := range items {
		if !it.Disabled {
			return i
		}
	}
	return -1
}

func move(items []Item, cur, step int) int {
	for i := cur + step; i >= 0 && i < len(items); i += step {
		if !items[i].Disabled {
			return i
		}
	}
	return cur
}

// clean drops control characters so a label from the portal cannot drive
// the terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

func render(w io.Writer, title string, items []Item, cur int) int {
	var b strings.Builder
	lines := 0
	if title != "" {
		fmt.Fprintf(&b, "%s\r\n", clean(title))
		lines++
	}
	for i, it := range items {
		marker := "  "
		if i == cur {
			marker = "> "
		}
		line := marker + clean(it.Label)
		if it.Detail != "" {
			line += "  " + clean(it.Detail)
		}
		if it.Disabled {
			line = "\x1b[2m" + line + "\x1b[0m"
		} else if i == cur {
			line = "\x1b[1m" + line + "\x1b[0m"
		}
		b.WriteString("\x1b[2K" + line + "\r\n")
		lines++
	}
	b.WriteString("\x1b[2K\x1b[2m(arrows to move, Enter to choose, Esc to cancel)\x1b[0m")
	_, _ = io.WriteString(w, b.String())
	return lines
}

func erase(w io.Writer, lines int) {
	if lines > 0 {
		_, _ = fmt.Fprintf(w, "\r\x1b[%dA\x1b[J", lines)
	} else {
		_, _ = io.WriteString(w, "\r\x1b[J")
	}
}

// run is the terminal-independent loop, tested with scripted input.
func run(ctx context.Context, next nextByte, w io.Writer, title string, items []Item) (int, error) {
	cur := firstEnabled(items)
	if cur < 0 {
		return -1, ErrNoChoice
	}
	_, _ = io.WriteString(w, "\x1b[?25l") // hide cursor
	defer io.WriteString(w, "\x1b[?25h")
	lines := render(w, title, items, cur)
	defer func() { erase(w, lines) }()
	for {
		if err := ctx.Err(); err != nil {
			return -1, ErrCanceled
		}
		k, ok, err := readKey(next)
		if err != nil {
			return -1, fmt.Errorf("%w: %v", ErrCanceled, err)
		}
		if !ok {
			continue
		}
		prev := cur
		switch k {
		case keyEnter:
			return cur, nil
		case keyCancel:
			return -1, ErrCanceled
		case keyUp:
			cur = move(items, cur, -1)
		case keyDown:
			cur = move(items, cur, 1)
		case keyHome:
			cur = move(items, -1, 1)
		case keyEnd:
			cur = move(items, len(items), -1)
		}
		if cur != prev {
			erase(w, lines)
			lines = render(w, title, items, cur)
		}
	}
}
