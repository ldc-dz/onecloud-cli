package cli

import (
	"context"
	"net"
	"time"
)

// lookupHost is replaced in tests.
var lookupHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// shellServiceAddress resolves the instance service name in the cluster DNS
// of OneCloud Shell and returns its private IPv4 when the port answers, or ""
// so the caller keeps its normal path. TLS still verifies the certificate
// name (host=) and OAuth still signs the user in: this only picks the route.
func shellServiceAddress(name string, port int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := lookupHost(ctx, name)
	if err != nil {
		debugf("tenant-network lookup of %s: %v", name, err)
		return ""
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
			continue
		}
		if probeTCP(a, port) {
			return a
		}
	}
	return ""
}
