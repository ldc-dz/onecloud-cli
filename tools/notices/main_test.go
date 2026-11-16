package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The committed NOTICE and THIRD_PARTY_NOTICES.md must match what the linked
// modules require today. This is the gate that keeps a release from shipping
// without the license texts of what it links.
func TestNoticesAreCurrent(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	generated, err := generate(root)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range generated {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("%s: %v (run `make notices`)", name, err)
		}
		if string(got) != want {
			t.Errorf("%s is out of date: run `make notices` and commit the result", name)
		}
	}
}

// Every linked module needs a recognized license, and the generated file
// must carry one text per license file.
func TestEveryLinkedModuleHasALicenseText(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	mods, err := linkedModules(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) == 0 {
		t.Fatal("no linked module found")
	}
	notices, err := os.ReadFile(filepath.Join(root, thirdPartyOut))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range mods {
		if err := collect(m); err != nil {
			t.Error(err)
			continue
		}
		if len(m.licenses()) == 0 {
			t.Errorf("%s: no license identifier", m.Path)
		}
		for _, f := range m.Files {
			if !strings.Contains(string(notices), f.Text) {
				t.Errorf("%s: %s is not reproduced in %s", m.Path, f.Rel, thirdPartyOut)
			}
		}
	}
}

// Upstream NOTICE files must be reproduced in NOTICE (Apache-2.0, 4(d)).
func TestUpstreamNoticesAreInNotice(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	mods, err := linkedModules(root)
	if err != nil {
		t.Fatal(err)
	}
	notice, err := os.ReadFile(filepath.Join(root, noticeOut))
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, m := range mods {
		if err := collect(m); err != nil {
			t.Fatal(err)
		}
		for _, f := range m.Files {
			if f.Kind != kindNotice {
				continue
			}
			found++
			if !strings.Contains(string(notice), f.Text) {
				t.Errorf("%s: %s is not reproduced in %s", m.Path, f.Rel, noticeOut)
			}
		}
	}
	if found == 0 {
		t.Fatal("no upstream NOTICE file found: the AWS SDK alone ships one")
	}
}

func TestTargetsMatchMakefile(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^TARGETS\s*:=\s*(.+)$`).FindSubmatch(makefile)
	if match == nil {
		t.Fatal("TARGETS not found in the Makefile")
	}
	if got := strings.Fields(string(match[1])); !reflect.DeepEqual(got, targets) {
		t.Fatalf("Makefile TARGETS %v differ from the notice targets %v", got, targets)
	}
}

// The embedded Go license must be the one of the toolchain that builds ocd.
// Distribution packages may install it elsewhere; the official toolchain and
// the CI image keep it in GOROOT.
func TestGoLicenseMatchesToolchain(t *testing.T) {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	goroot := strings.TrimSpace(string(out))
	for _, name := range []string{"LICENSE", "PATENTS"} {
		embedded, err := golang.ReadFile("golang/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if len(embedded) == 0 {
			t.Fatalf("embedded Go %s is empty", name)
		}
		toolchain, err := os.ReadFile(filepath.Join(goroot, name))
		if err != nil {
			continue
		}
		if clean(string(toolchain)) != clean(string(embedded)) {
			t.Errorf("tools/notices/golang/%s differs from %s/%s: copy the new text", name, goroot, name)
		}
	}
}

func TestFileKind(t *testing.T) {
	cases := map[string]string{
		"LICENSE":          kindLicense,
		"LICENSE.txt":      kindLicense,
		"LICENSE.md":       kindLicense,
		"License-MIT":      kindLicense,
		"LICENSE_list":     kindLicense,
		"LICENCE":          kindLicense,
		"COPYING":          kindLicense,
		"UNLICENSE":        kindLicense,
		"COPYRIGHT":        kindCopyright,
		"PATENTS":          kindPatents,
		"NOTICE":           kindNotice,
		"NOTICE.txt":       kindNotice,
		"license.go":       "",
		"licenses.json":    "",
		"notice_test.go":   "",
		"LICENSES":         "",
		"README.md":        "",
		"AUTHORS":          "",
		"CONTRIBUTORS":     "",
		"noticeboard.txt":  "",
		"copyrights.yaml":  "",
		"patents_test.go":  "",
		"unlicensed.proto": "",
	}
	for name, want := range cases {
		if got := fileKind(name); got != want {
			t.Errorf("fileKind(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	const (
		mit = "Permission is hereby granted, free of charge, to any person obtaining a copy of this software. " +
			"The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software."
		bsd2 = "Redistribution and use in source and binary forms, with or without modification, are permitted. " +
			"Redistributions in binary form must reproduce the above copyright notice, this list of conditions."
		bsd3   = bsd2 + " Neither the name of the copyright holder nor the names of its contributors may be used."
		apache = "Apache License\nVersion 2.0, January 2004\nTERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION"
		isc    = "Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted"
		mpl    = "Mozilla Public License Version 2.0 ... Secondary License means either the GNU General Public License, Version 2.0"
	)
	good := []struct {
		name, text string
		want       []string
	}{
		{"mit", mit, []string{"MIT"}},
		{"mit wrapped and curly quotes", strings.ReplaceAll(mit, " ", "\n  "), []string{"MIT"}},
		{"bsd2", bsd2, []string{"BSD-2-Clause"}},
		{"bsd3", bsd3, []string{"BSD-3-Clause"}},
		{"apache", apache, []string{"Apache-2.0"}},
		{"isc", isc, []string{"ISC"}},
		{"mpl cites the GPL as a secondary license", mpl, []string{"MPL-2.0"}},
		{"unlicense", "This is free and unencumbered software released into the public domain, commercial or non-commercial.", []string{"Unlicense"}},
		{"cc0", "CC0 1.0 Universal", []string{"CC0-1.0"}},
		{"two licenses in one file", apache + "\n\n" + bsd3, []string{"Apache-2.0", "BSD-3-Clause"}},
	}
	for _, c := range good {
		got, err := classify(c.text)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, %v; want %v", c.name, got, err, c.want)
		}
	}
	bad := map[string]string{
		"empty":              "",
		"unknown terms":      "You may use this software on Tuesdays.",
		"gpl":                "GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007",
		"lgpl":               "GNU Lesser General Public License version 2.1",
		"agpl":               "GNU AFFERO GENERAL PUBLIC LICENSE",
		"mit or gpl":         mit + " Alternatively, the GNU General Public License applies.",
		"commons clause":     apache + " Commons Clause License Condition v1.0",
		"business source":    "Business Source License 1.1",
		"sspl":               "Server Side Public License VERSION 1",
		"bsd advertising":    bsd3 + " All advertising materials mentioning features or use of this software must display",
		"official builds":    "POMERIUM COMMUNITY EDITION LICENSE VERSION 1.0 " + apache,
		"cc by":              "Creative Commons Attribution 4.0 International",
		"mit without notice": "Permission is hereby granted, free of charge, to any person obtaining a copy of this software.",
	}
	for name, text := range bad {
		if got, err := classify(text); err == nil {
			t.Errorf("%s: accepted as %v", name, got)
		}
	}
}

func TestCleanKeepsTheWording(t *testing.T) {
	got := clean("\ufeff\r\n  Copyright (c) Caf\u00e9  \r\n\tAll rights reserved.\t\r\n\r\n")
	if want := "  Copyright (c) Caf\u00e9\n\tAll rights reserved.\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFenceIsLongerThanTheText(t *testing.T) {
	if got := fence("plain\ntext\n"); got != "~~~" {
		t.Fatalf("got %q", got)
	}
	if got := fence("a\n  ~~~~ inner\nb\n"); got != "~~~~~" {
		t.Fatalf("got %q", got)
	}
}
