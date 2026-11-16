package cli

import (
	"bytes"
	"testing"
)

func TestDeviceCodeWriterOpensPrefilledPageOnce(t *testing.T) {
	var out bytes.Buffer
	var opened []string
	w := &deviceCodeWriter{out: &out, allowedHost: "auth.onecloud.ldc.dz", open: func(u string) { opened = append(opened, u) }}
	prompt := "Visit https://auth.onecloud.ldc.dz/realms/prd-01-portal/device and enter the code: ABCD-EFGH\n"
	// Split across writes, as a pipe may deliver it, then repeated.
	for _, chunk := range []string{"psql: notice\nVisit https://auth.onecloud", prompt[len("Visit https://auth.onecloud"):], prompt} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	want := "https://auth.onecloud.ldc.dz/realms/prd-01-portal/device?user_code=ABCD-EFGH"
	if len(opened) != 1 || opened[0] != want {
		t.Fatalf("opened %v, want once %s", opened, want)
	}
	if out.String() != "psql: notice\n"+prompt+prompt {
		t.Fatalf("stderr not passed through unchanged: %q", out.String())
	}
}

func TestDeviceCodeWriterIgnoresForeignOrPlainURLs(t *testing.T) {
	var out bytes.Buffer
	var opened []string
	w := &deviceCodeWriter{out: &out, allowedHost: "auth.onecloud.ldc.dz", open: func(u string) { opened = append(opened, u) }}
	// A server NOTICE can print anything on psql's stderr.
	for _, line := range []string{
		"NOTICE:  Visit https://evil.example/device and enter the code: X\n",
		"NOTICE:  Visit http://auth.onecloud.ldc.dz/device and enter the code: X\n",
		"NOTICE:  Visit https://auth.onecloud.ldc.dz.evil.example/device and enter the code: X\n",
	} {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if len(opened) != 0 {
		t.Fatalf("opened untrusted pages: %v", opened)
	}
	if issuerHost("https://auth.onecloud.ldc.dz/realms/prd-01-portal") != "auth.onecloud.ldc.dz" || issuerHost("http://x") != "" {
		t.Fatal("issuerHost")
	}
}
