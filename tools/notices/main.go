// Command notices generates the third-party attribution files shipped in
// every ocd release archive.
//
// It lists the packages linked into ./cmd/ocd for every release target,
// collects the license, copyright, patent and notice files of their modules
// from the module cache, and writes:
//
//   - THIRD_PARTY_NOTICES.md: a summary table and the full texts;
//   - NOTICE: the ocd notice followed by the upstream NOTICE files, which the
//     Apache License 2.0, section 4(d), requires to be kept.
//
// It fails when a linked module ships no license file or when a license is
// not one of the reviewed identifiers, so a new dependency cannot ship
// without a look at its terms.
//
// Usage:
//
//	go run ./tools/notices          # rewrite both files
//	go run ./tools/notices -check   # exit 1 when a file is out of date
package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// targets are the release platforms. Keep them in step with TARGETS in the
// Makefile (a test compares the two).
var targets = []string{
	"linux/amd64", "linux/arm64",
	"darwin/amd64", "darwin/arm64",
	"windows/amd64", "windows/arm64",
}

const (
	mainPackage   = "./cmd/ocd"
	thirdPartyOut = "THIRD_PARTY_NOTICES.md"
	noticeOut     = "NOTICE"
)

// The Go license and patent grant: the binary links the Go runtime and
// standard library. Copied from https://github.com/golang/go at the release
// tag; a test compares them with the toolchain's own copy when it has one.
//
//go:embed golang/LICENSE golang/PATENTS
var golang embed.FS

// File kinds, in the order they are printed inside a module section.
const (
	kindLicense   = "license"
	kindCopyright = "copyright"
	kindPatents   = "patents"
	kindNotice    = "notice"
)

type file struct {
	Rel  string   // path inside the module, slash separated
	Kind string   // one of the kind constants
	Text string   // normalized text
	IDs  []string // SPDX identifiers (license files only)
}

type module struct {
	Path    string
	Source  string
	Dir     string
	Targets []string
	Files   []file

	pkgDirs map[string]bool
	targets map[string]bool
}

func main() {
	check := flag.Bool("check", false, "verify the committed files instead of writing them")
	flag.Parse()
	root, err := repoRoot()
	if err == nil {
		err = run(root, *check, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

func run(root string, check bool, out io.Writer) error {
	generated, err := generate(root)
	if err != nil {
		return err
	}
	var stale []string
	for _, name := range []string{thirdPartyOut, noticeOut} {
		path := filepath.Join(root, name)
		current, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if bytes.Equal(current, []byte(generated[name])) {
			continue
		}
		if check {
			stale = append(stale, name)
			continue
		}
		if err := os.WriteFile(path, []byte(generated[name]), 0o644); err != nil {
			return err
		}
		fmt.Fprintln(out, "wrote", name)
	}
	if len(stale) > 0 {
		return fmt.Errorf("%s out of date: run `make notices` and commit the result", strings.Join(stale, " and "))
	}
	return nil
}

// generate returns the content of both files, keyed by file name.
func generate(root string) (map[string]string, error) {
	mods, err := linkedModules(root)
	if err != nil {
		return nil, err
	}
	for _, m := range mods {
		if err := collect(m); err != nil {
			return nil, err
		}
	}
	goMod, err := goModule()
	if err != nil {
		return nil, err
	}
	all := append([]*module{goMod}, mods...)
	return map[string]string{
		thirdPartyOut: renderThirdParty(all),
		noticeOut:     renderNotice(all),
	}, nil
}

// repoRoot walks up from the working directory to the directory of go.mod.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found above the working directory")
		}
		dir = parent
	}
}

// listedPackage is the part of `go list -json` this tool reads.
type listedPackage struct {
	Dir      string
	Standard bool
	Module   *struct {
		Path    string
		Dir     string
		Main    bool
		Replace *struct{ Dir string }
	}
}

// linkedModules returns the modules that provide at least one package linked
// into the binary on at least one release target, sorted by path.
func linkedModules(root string) ([]*module, error) {
	byPath := map[string]*module{}
	for _, target := range targets {
		goos, goarch, _ := strings.Cut(target, "/")
		cmd := exec.Command("go", "list", "-deps", "-json=Dir,Standard,Module", mainPackage)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list for %s: %w\n%s", target, err, stderr.String())
		}
		dec := json.NewDecoder(bytes.NewReader(out))
		for dec.More() {
			var p listedPackage
			if err := dec.Decode(&p); err != nil {
				return nil, fmt.Errorf("go list for %s: %w", target, err)
			}
			if p.Standard || p.Module == nil || p.Module.Main {
				continue
			}
			dir := p.Module.Dir
			if p.Module.Replace != nil && p.Module.Replace.Dir != "" {
				dir = p.Module.Replace.Dir
			}
			if dir == "" {
				return nil, fmt.Errorf("module %s is not in the module cache: run `go mod download`", p.Module.Path)
			}
			m := byPath[p.Module.Path]
			if m == nil {
				m = &module{
					Path:    p.Module.Path,
					Source:  "https://pkg.go.dev/" + p.Module.Path,
					Dir:     dir,
					pkgDirs: map[string]bool{},
					targets: map[string]bool{},
				}
				byPath[p.Module.Path] = m
			}
			m.pkgDirs[p.Dir] = true
			m.targets[target] = true
		}
	}
	mods := make([]*module, 0, len(byPath))
	for _, m := range byPath {
		for _, target := range targets {
			if m.targets[target] {
				m.Targets = append(m.Targets, target)
			}
		}
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	return mods, nil
}

// collect reads the attribution files of a module: those at its root and
// those next to, or above, a linked package (a sub-directory can carry its
// own license). Files of directories that are not linked are left out.
func collect(m *module) error {
	dirs := map[string]bool{m.Dir: true}
	for dir := range m.pkgDirs {
		for strings.HasPrefix(dir, m.Dir) && dir != m.Dir {
			dirs[dir] = true
			dir = filepath.Dir(dir)
		}
	}
	for dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			kind := fileKind(entry.Name())
			if kind == "" || !entry.Type().IsRegular() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(m.Dir, path)
			if err != nil {
				return err
			}
			f := file{Rel: filepath.ToSlash(rel), Kind: kind, Text: clean(string(data))}
			if kind == kindLicense {
				if f.IDs, err = classify(f.Text); err != nil {
					return fmt.Errorf("%s: %s: %w", m.Path, f.Rel, err)
				}
			}
			m.Files = append(m.Files, f)
		}
	}
	sortFiles(m.Files)
	if len(m.licenses()) == 0 {
		return fmt.Errorf("%s ships no license file: pin a version that has one, or drop the dependency", m.Path)
	}
	return nil
}

// goModule is the entry for the Go runtime and standard library.
func goModule() (*module, error) {
	m := &module{Path: "Go standard library and runtime", Source: "https://go.dev/dl/", Targets: targets}
	for _, f := range []file{{Rel: "LICENSE", Kind: kindLicense}, {Rel: "PATENTS", Kind: kindPatents}} {
		data, err := golang.ReadFile("golang/" + f.Rel)
		if err != nil {
			return nil, err
		}
		f.Text = clean(string(data))
		if f.Kind == kindLicense {
			if f.IDs, err = classify(f.Text); err != nil {
				return nil, fmt.Errorf("go: %s: %w", f.Rel, err)
			}
		}
		m.Files = append(m.Files, f)
	}
	return m, nil
}

// licenses returns the sorted SPDX identifiers of a module.
func (m *module) licenses() []string {
	seen := map[string]bool{}
	var ids []string
	for _, f := range m.Files {
		for _, id := range f.IDs {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func sortFiles(files []file) {
	order := map[string]int{kindLicense: 0, kindCopyright: 1, kindPatents: 2, kindNotice: 3}
	sort.Slice(files, func(i, j int) bool {
		a, b := files[i], files[j]
		if da, db := strings.Count(a.Rel, "/"), strings.Count(b.Rel, "/"); da != db {
			return da < db // the module root first
		}
		if order[a.Kind] != order[b.Kind] {
			return order[a.Kind] < order[b.Kind]
		}
		return a.Rel < b.Rel
	})
}

// notSource lists extensions of files that share a license-like name but are
// code or data (license.go, notice.json).
var notSource = map[string]bool{
	".go": true, ".s": true, ".c": true, ".h": true, ".cc": true, ".cpp": true,
	".py": true, ".sh": true, ".js": true, ".ts": true, ".json": true,
	".yaml": true, ".yml": true, ".toml": true, ".tmpl": true, ".tpl": true,
	".html": true, ".css": true, ".proto": true, ".mod": true, ".sum": true,
	".svg": true, ".png": true,
}

// fileKind tells whether a file name is an attribution file, and which kind.
func fileKind(name string) string {
	lower := strings.ToLower(name)
	if notSource[filepath.Ext(lower)] {
		return ""
	}
	for _, c := range []struct{ prefix, kind string }{
		{"license", kindLicense}, {"licence", kindLicense},
		{"unlicense", kindLicense}, {"unlicence", kindLicense},
		{"copying", kindLicense},
		{"copyright", kindCopyright},
		{"patents", kindPatents},
		{"notice", kindNotice},
	} {
		rest, ok := strings.CutPrefix(lower, c.prefix)
		if ok && (rest == "" || strings.ContainsRune("._-", rune(rest[0]))) {
			return c.kind
		}
	}
	return ""
}

// clean normalizes line ends and trailing blanks; the wording is untouched.
func clean(text string) string {
	text = strings.TrimPrefix(text, "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.Trim(strings.Join(lines, "\n"), "\n") + "\n"
}

// Markers of terms that need a legal review before ocd can ship them. The
// copyleft names are only checked outside MPL-2.0, whose text cites them as
// secondary licenses.
var (
	restricted = []string{
		"commons clause", "business source license", "server side public license",
		"elastic license", "creative commons attribution", "community edition license",
	}
	copyleft = []string{
		"gnu general public license", "gnu lesser general public license",
		"gnu affero general public license",
	}
)

// classify returns the SPDX identifiers of the reviewed licenses found in a
// license text. A text with no reviewed license, or with restrictive terms,
// is an error: the build stops until someone has read it.
func classify(text string) ([]string, error) {
	t := strings.ToLower(text)
	t = strings.NewReplacer("\u201c", `"`, "\u201d", `"`, "\u2018", "'", "\u2019", "'").Replace(t)
	t = strings.Join(strings.Fields(t), " ")
	has := func(markers ...string) bool {
		for _, m := range markers {
			if !strings.Contains(t, m) {
				return false
			}
		}
		return true
	}
	firstOf := func(markers []string) string {
		for _, m := range markers {
			if strings.Contains(t, m) {
				return m
			}
		}
		return ""
	}

	var ids []string
	if has("apache license", "version 2.0", "terms and conditions for use, reproduction, and distribution") {
		ids = append(ids, "Apache-2.0")
	}
	if has("permission is hereby granted, free of charge, to any person obtaining a copy",
		"the above copyright notice and this permission notice shall be included in all copies or substantial portions") {
		ids = append(ids, "MIT")
	}
	if has("redistribution and use in source and binary forms",
		"redistributions in binary form must reproduce the above copyright notice") {
		switch {
		case has("all advertising materials"):
			return nil, errors.New("BSD license with an advertising clause: needs a legal review")
		case has("neither the name"), has("may not be used to endorse or promote products"):
			ids = append(ids, "BSD-3-Clause")
		default:
			ids = append(ids, "BSD-2-Clause")
		}
	}
	if has("permission to use, copy, modify, and", "distribute this software for any purpose with or without fee is hereby granted") {
		ids = append(ids, "ISC")
	}
	mpl := has("mozilla public license", "version 2.0")
	if mpl {
		ids = append(ids, "MPL-2.0")
	}
	if has("this is free and unencumbered software released into the public domain") {
		ids = append(ids, "Unlicense")
	}
	if has("cc0 1.0 universal") {
		ids = append(ids, "CC0-1.0")
	}

	if m := firstOf(restricted); m != "" {
		return nil, fmt.Errorf("restrictive terms (%q): needs a legal review", m)
	}
	if !mpl {
		if m := firstOf(copyleft); m != "" {
			return nil, fmt.Errorf("copyleft terms (%q): needs a legal review", m)
		}
	}
	if len(ids) == 0 {
		return nil, errors.New("license not recognized: read it, then teach tools/notices about it")
	}
	sort.Strings(ids)
	return ids, nil
}

// fence returns a tilde fence longer than any tilde run that opens a line.
func fence(text string) string {
	n := 3
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimLeft(line, " ")
		if run := len(line) - len(strings.TrimLeft(line, "~")); run >= n {
			n = run + 1
		}
	}
	return strings.Repeat("~", n)
}

func targetsLabel(list []string) string {
	if len(list) == len(targets) {
		return "all"
	}
	return strings.Join(list, ", ")
}

const thirdPartyHeader = `# Third-party notices

` + "`ocd`" + ` is distributed as a single binary. It links the Go standard library and
the Go modules listed below. This file reproduces their license texts,
copyright notices and patent grants, as those licenses require for binary
redistribution. The attribution notices that the Apache License 2.0 requires
to be kept (upstream ` + "`NOTICE`" + ` files) are also reproduced in ` + "`NOTICE`" + `.

This file is generated by ` + "`make notices`" + ` from the packages actually linked
into the binary for each release target. ` + "`make test`" + ` fails when it is out of
date, when a linked module ships no license file, or when a license is not one
of the reviewed identifiers of the summary. Do not edit it by hand.

Versions: the exact version of every module is recorded in ` + "`go.mod`" + ` at the
release tag and inside each released binary (` + "`go version -m ocd`" + `).

Source code: every module below is used unmodified and its source is
available from the address in its section and from the Go module proxy
(` + "`go mod download <module>@<version>`" + `). This is the source notice for the
modules under the Mozilla Public License 2.0 (section 3.2).
`

func renderThirdParty(mods []*module) string {
	var b strings.Builder
	b.WriteString(thirdPartyHeader)
	b.WriteString("\n## Summary\n\n| Component | License | Release targets |\n|---|---|---|\n")
	for _, m := range mods {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", m.Path, strings.Join(m.licenses(), " AND "), targetsLabel(m.Targets))
	}
	for _, m := range mods {
		fmt.Fprintf(&b, "\n## %s\n\nSource: <%s>\n", m.Path, m.Source)
		for _, f := range m.Files {
			title := f.Rel
			if len(f.IDs) > 0 {
				title += " (" + strings.Join(f.IDs, " AND ") + ")"
			}
			fc := fence(f.Text)
			fmt.Fprintf(&b, "\n### %s: %s\n\n%stext\n%s%s\n", m.Path, title, fc, f.Text, fc)
		}
	}
	return b.String()
}

const noticeHeader = `ocd - OneCloud CLI
Copyright 2026 LDC

This product is licensed under the Apache License, Version 2.0 (see LICENSE).

It embeds opkssh and OpenPubkey (the OpenPubkey project) and the Pomerium
command-line transport (Pomerium, Inc.), all under the Apache License,
Version 2.0, together with the other third-party software listed in
THIRD_PARTY_NOTICES.md. That file reproduces the license texts, copyright
notices and patent grants of everything ocd links.

The attribution notices below come from the NOTICE files of the third-party
software linked into ocd. They are reproduced unchanged, one block per file,
as the Apache License, Version 2.0, section 4(d), requires. This section is
generated by "make notices"; do not edit it by hand.
`

func renderNotice(mods []*module) string {
	var b strings.Builder
	b.WriteString(noticeHeader)
	rule := strings.Repeat("=", 78)
	for _, m := range mods {
		for _, f := range m.Files {
			if f.Kind != kindNotice {
				continue
			}
			fmt.Fprintf(&b, "\n%s\n%s (%s)\n%s\n\n%s", rule, m.Path, f.Rel, rule, f.Text)
		}
	}
	return b.String()
}
