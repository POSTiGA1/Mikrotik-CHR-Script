package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parhamfa/chr-install/internal/model"
)

type fixtureRunner struct {
	responses map[string][]byte
}

func (runner fixtureRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	if value, ok := runner.responses[key]; ok {
		return value, nil
	}
	return nil, fmt.Errorf("unexpected command: %s", key)
}

func (fixtureRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

type fixtureProber struct {
	result model.DHCPProbe
}

func (probe fixtureProber) Probe(_ context.Context, _ string, _ net.HardwareAddr, _ time.Duration) (model.DHCPProbe, error) {
	return probe.result, nil
}

func TestDetectCraftikStaticNetwork(t *testing.T) {
	root := filepath.Join("testdata", "craftik")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	runner := fixtureRunner{responses: map[string][]byte{
		"ip -j -4 route show table main": read("routes4.json"),
		"ip -j -6 route show table main": read("routes6.json"),
		"ip -j -4 rule show":             read("rules4.json"),
		"ip -j -6 rule show":             read("rules6.json"),
		"ip -j address show":             read("addresses.json"),
		"ip -j link show dev ens3":       read("link.json"),
		"ip -j address show dev ens3":    read("addresses.json"),
	}}
	plan, issues := Detect(context.Background(), runner, fixtureProber{result: model.DHCPProbe{Attempted: true, Offered: false}}, root)
	for _, issue := range issues {
		if issue.Severity == model.SeverityBlocker {
			t.Fatalf("unexpected blocker: %#v", issue)
		}
	}
	if plan.InterfaceName != "ens3" || plan.MAC != "D2:CB:48:5C:3E:71" || plan.MTU != 1500 {
		t.Fatalf("unexpected uplink: %#v", plan)
	}
	if plan.Driver != "virtio_net" {
		t.Fatalf("unexpected uplink driver: %q", plan.Driver)
	}
	if plan.IPv4.Mode != "static" || len(plan.IPv4.Addresses) != 1 || plan.IPv4.Addresses[0] != "45.135.242.144/24" {
		t.Fatalf("unexpected IPv4 plan: %#v", plan.IPv4)
	}
	if plan.IPv4.Gateway != "45.135.242.1" || plan.IPv4.GatewayOnLink {
		t.Fatalf("unexpected gateway: %#v", plan.IPv4)
	}
	if strings.Join(plan.DNS, ",") != "8.8.8.8,217.218.127.127" {
		t.Fatalf("unexpected DNS: %#v", plan.DNS)
	}
	if plan.DHCPProbe.Offered {
		t.Fatal("craftik fixture must not have DHCP")
	}
}

func TestDynamicAddressWithoutLeaseOrOfferIsBlocked(t *testing.T) {
	root := filepath.Join("testdata", "craftik")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	runner := fixtureRunner{responses: map[string][]byte{
		"ip -j -4 route show table main": []byte(`[{"dst":"default","gateway":"192.0.2.1","dev":"ens3","protocol":"dhcp","metric":100}]`),
		"ip -j -6 route show table main": read("routes6.json"),
		"ip -j -4 rule show":             read("rules4.json"),
		"ip -j -6 rule show":             read("rules6.json"),
		"ip -j address show":             []byte(`[{"ifindex":2,"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.20","prefixlen":24,"scope":"global","dynamic":true,"protocol":"dhcp"}]}]`),
		"ip -j link show dev ens3":       read("link.json"),
		"ip -j address show dev ens3":    []byte(`[{"ifindex":2,"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.20","prefixlen":24,"scope":"global","dynamic":true,"protocol":"dhcp"}]}]`),
	}}
	plan, issues := Detect(context.Background(), runner, fixtureProber{result: model.DHCPProbe{Attempted: true, Offered: false}}, root)
	if plan.IPv4.Mode != "dhcp" {
		t.Fatalf("expected DHCP plan, got %#v", plan.IPv4)
	}
	if plan.Evidence != model.EvidenceInferred {
		t.Fatalf("unverified DHCP plan was labeled %q", plan.Evidence)
	}
	found := false
	for _, issue := range issues {
		found = found || issue.Code == "dhcp-unverified" && issue.Severity == model.SeverityBlocker
	}
	if !found {
		t.Fatalf("expected DHCP evidence blocker, got %#v", issues)
	}
}

func TestSupportedNetworkDrivers(t *testing.T) {
	for _, driver := range []string{"virtio_net", "e1000", "vmxnet3", "hv_netvsc", "xen-netfront"} {
		if !supportedNetworkDriver(driver) {
			t.Fatalf("expected %s to be supported", driver)
		}
	}
	if supportedNetworkDriver("mystery_nic") {
		t.Fatal("unknown network driver must fail closed")
	}
}

func TestRouterOSOffLinkStaticPlan(t *testing.T) {
	plan := model.NetworkPlan{
		InterfaceName: "ens3",
		MAC:           "02:00:00:00:00:01",
		MTU:           1500,
		IPv4: model.IPv4Plan{
			Mode:          "static",
			Addresses:     []string{"192.0.2.10/32"},
			Gateway:       "192.0.2.1",
			GatewayOnLink: true,
		},
		IPv6: model.IPv6Plan{
			Addresses:     []string{"2001:db8:1::10/128"},
			Gateway:       "2001:db8:2::1",
			GatewayOnLink: true,
		},
	}
	if err := Validate(plan); err != nil {
		t.Fatal(err)
	}
	script, err := RouterOSScript(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"mac-address=$targetMac",
		"/ip/dhcp-client/remove [find where interface=$uplinkName]",
		"/ip/address/remove [find where interface=$uplinkName and dynamic=no]",
		"accept-router-advertisements=no",
		"address=192.0.2.10/32",
		"dst-address=192.0.2.1/32 gateway=$uplinkName scope=10",
		"dst-address=0.0.0.0/0 gateway=192.0.2.1 target-scope=11",
		"address=2001:db8:1::10/128",
		"dst-address=2001:db8:2::1/128 gateway=$uplinkName scope=10",
		"dst-address=::/0 gateway=2001:db8:2::1 target-scope=11",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("script does not contain %q:\n%s", expected, script)
		}
	}
}

func TestRouterOSConnectedGatewaysKeepDefaultTargetScope(t *testing.T) {
	plan := model.NetworkPlan{
		InterfaceName: "ens3",
		MAC:           "02:00:00:00:00:01",
		MTU:           1500,
		IPv4: model.IPv4Plan{
			Mode:      "static",
			Addresses: []string{"192.0.2.10/24"},
			Gateway:   "192.0.2.1",
		},
		IPv6: model.IPv6Plan{
			Addresses: []string{"2001:db8::10/64"},
			Gateway:   "2001:db8::1",
		},
	}
	script, err := RouterOSScript(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "target-scope=11") {
		t.Fatalf("directly connected gateway unexpectedly uses recursive target scope:\n%s", script)
	}
}

func TestGatewayOutside(t *testing.T) {
	if gatewayOutside("192.0.2.1", []string{"192.0.2.10/24"}) {
		t.Fatal("same-subnet gateway reported off-link")
	}
	if !gatewayOutside("192.0.2.1", []string{"198.51.100.10/32"}) {
		t.Fatal("routed gateway was not reported off-link")
	}
}

func TestSelectDefaultRejectsLowerPriorityFailover(t *testing.T) {
	selected, issue := selectDefault([]route{
		{Destination: "default", Gateway: "192.0.2.1", Device: "ens3", Metric: 100},
		{Destination: "default", Gateway: "198.51.100.1", Device: "ens4", Metric: 200},
	}, "IPv4")
	if selected == nil || issue == nil || issue.Code != "multiple-defaults" {
		t.Fatalf("expected distinct default routes to be blocked: selected=%#v issue=%#v", selected, issue)
	}
}

func TestInspectRouteSetRejectsUntranslatedStaticRoute(t *testing.T) {
	defaultRoute := &route{Destination: "default", Gateway: "192.0.2.1", Device: "ens3"}
	issues := inspectRouteSet([]route{
		*defaultRoute,
		{Destination: "192.0.2.0/24", Device: "ens3", Protocol: "kernel"},
		{Destination: "203.0.113.0/24", Gateway: "192.0.2.2", Device: "ens3", Protocol: "static"},
	}, defaultRoute, "ens3", "IPv4", false)
	if len(issues) != 1 || issues[0].Code != "unsupported-route" {
		t.Fatalf("expected only the untranslated route to block, got %#v", issues)
	}
}

func TestInspectRouteSetAllowsBareGatewayHostRoute(t *testing.T) {
	defaultRoute := &route{Destination: "default", Gateway: "10.0.0.1", Device: "net0", Protocol: "static"}
	issues := inspectRouteSet([]route{
		*defaultRoute,
		{Destination: "10.0.0.1", Device: "net0", Protocol: "static", Scope: "link"},
	}, defaultRoute, "net0", "IPv4", false)
	if len(issues) != 0 {
		t.Fatalf("gateway host route was rejected: %#v", issues)
	}
}

func TestDetectAllowsVultrDHCPRoutesThatMatchDefaultPath(t *testing.T) {
	root := t.TempDir()
	writeFixture := func(relative, content string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture("sys/class/net/enp1s0/device/driver", "virtio_net\n")
	writeFixture("etc/netplan/50-cloud-init.yaml", "network:\n  ethernets:\n    enp1s0:\n      dhcp4: true\n      match:\n        macaddress: 56:00:06:7a:66:0f\n")
	writeFixture("etc/resolv.conf", "nameserver 108.61.10.10\n")
	writeFixture("run/systemd/netif/leases/2", "ADDRESS=70.34.254.194\nDNS=108.61.10.10\nCLASSLESS_ROUTES=0.0.0.0/0,70.34.254.1 169.254.169.254/32,70.34.254.1\n")

	routes := []byte(`[
		{"type":"unicast","dst":"default","gateway":"70.34.254.1","dev":"enp1s0","protocol":"dhcp","scope":"global","prefsrc":"70.34.254.194","metric":100,"flags":[]},
		{"type":"unicast","dst":"70.34.254.0/23","dev":"enp1s0","protocol":"kernel","scope":"link","prefsrc":"70.34.254.194","metric":100,"flags":[]},
		{"type":"unicast","dst":"70.34.254.1","dev":"enp1s0","protocol":"dhcp","scope":"link","prefsrc":"70.34.254.194","metric":100,"flags":[]},
		{"type":"unicast","dst":"108.61.10.10","gateway":"70.34.254.1","dev":"enp1s0","protocol":"dhcp","scope":"global","prefsrc":"70.34.254.194","metric":100,"flags":[]},
		{"type":"unicast","dst":"169.254.169.254","gateway":"70.34.254.1","dev":"enp1s0","protocol":"dhcp","scope":"global","prefsrc":"70.34.254.194","metric":100,"flags":[]}
	]`)
	addresses := []byte(`[{"ifindex":2,"ifname":"enp1s0","link_type":"ether","address":"56:00:06:7a:66:0f","addr_info":[{"family":"inet","local":"70.34.254.194","prefixlen":23,"scope":"global","dynamic":true,"protocol":"dhcp"}]}]`)
	runner := fixtureRunner{responses: map[string][]byte{
		"ip -j -4 route show table main": routes,
		"ip -j -6 route show table main": []byte(`[]`),
		"ip -j -4 rule show":             []byte(`[{"priority":0,"table":"local"},{"priority":32766,"table":"main"},{"priority":32767,"table":"default"}]`),
		"ip -j -6 rule show":             []byte(`[{"priority":0,"table":"local"},{"priority":32766,"table":"main"}]`),
		"ip -j address show":             addresses,
		"ip -j link show dev enp1s0":     []byte(`[{"ifindex":2,"ifname":"enp1s0","mtu":1500,"address":"56:00:06:7a:66:0f","link_type":"ether"}]`),
		"ip -j address show dev enp1s0":  addresses,
	}}
	plan, issues := Detect(context.Background(), runner, fixtureProber{result: model.DHCPProbe{Attempted: true, Offered: true, Address: "70.34.254.194", Server: "169.254.169.254"}}, root)
	if plan.IPv4.Mode != "dhcp" || plan.IPv4.Evidence != model.EvidenceVerified {
		t.Fatalf("unexpected DHCP plan: %#v", plan.IPv4)
	}
	var redundant int
	for _, issue := range issues {
		if issue.Severity == model.SeverityBlocker {
			t.Fatalf("unexpected blocker: %#v", issue)
		}
		if issue.Code == "redundant-dhcp-route" {
			redundant++
		}
	}
	if redundant != 2 {
		t.Fatalf("expected both provider routes to be recognized, got %#v", issues)
	}
}

func TestRedundantDHCPRouteMustMatchEveryForwardingAttribute(t *testing.T) {
	base := `{"type":"unicast","dst":"%s","gateway":"192.0.2.1","dev":"ens3","protocol":"dhcp","scope":"global","prefsrc":"192.0.2.20","metric":100,"flags":[]%s}`
	decodePair := func(t *testing.T, defaultSuffix, candidateSuffix string) (route, *route) {
		t.Helper()
		data := fmt.Sprintf("["+base+","+base+"]", "default", defaultSuffix, "198.51.100.53", candidateSuffix)
		routes, err := decodeRoutes([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		return routes[1], &routes[0]
	}
	candidate, defaultRoute := decodePair(t, "", "")
	if !isRedundantDHCPRoute(candidate, defaultRoute) {
		t.Fatal("identical DHCP forwarding paths were not recognized")
	}
	issues := inspectRouteSet([]route{*defaultRoute, candidate}, defaultRoute, "ens3", "IPv4", false)
	if len(issues) != 1 || issues[0].Severity != model.SeverityBlocker || issues[0].Code != "unsupported-route" {
		t.Fatalf("DHCP exception escaped its DHCP-plan gate: %#v", issues)
	}
	candidate, defaultRoute = decodePair(t, `,"mtu":1400`, `,"mtu":1400`)
	if !isRedundantDHCPRoute(candidate, defaultRoute) {
		t.Fatal("matching additional forwarding attributes were rejected")
	}
	candidate, defaultRoute = decodePair(t, "", `,"mtu":1400`)
	if isRedundantDHCPRoute(candidate, defaultRoute) {
		t.Fatal("route with an additional MTU attribute was treated as redundant")
	}

	tests := []struct {
		name   string
		change func(*route, *route)
	}{
		{name: "candidate protocol", change: func(candidate, _ *route) { candidate.Protocol = "static" }},
		{name: "default protocol", change: func(_, defaultRoute *route) { defaultRoute.Protocol = "static" }},
		{name: "gateway", change: func(candidate, _ *route) { candidate.Gateway = "192.0.2.2" }},
		{name: "device", change: func(candidate, _ *route) { candidate.Device = "ens4" }},
		{name: "metric", change: func(candidate, _ *route) { candidate.Metric = 200 }},
		{name: "preferred source", change: func(candidate, _ *route) { candidate.PrefSource = "192.0.2.21" }},
		{name: "scope", change: func(candidate, _ *route) { candidate.Scope = "link" }},
		{name: "flags", change: func(candidate, _ *route) { candidate.Flags = []string{"onlink"} }},
		{name: "route type", change: func(candidate, _ *route) { candidate.Type = "blackhole" }},
		{name: "IPv6 destination", change: func(candidate, _ *route) { candidate.Destination = "2001:db8::53" }},
		{name: "invalid destination", change: func(candidate, _ *route) { candidate.Destination = "not-an-address" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := route{Type: "unicast", Destination: "198.51.100.53", Gateway: "192.0.2.1", Device: "ens3", Protocol: "dhcp", Scope: "global", PrefSource: "192.0.2.20", Metric: 100}
			defaultRoute := route{Type: "unicast", Destination: "default", Gateway: "192.0.2.1", Device: "ens3", Protocol: "dhcp", Scope: "global", PrefSource: "192.0.2.20", Metric: 100}
			test.change(&candidate, &defaultRoute)
			if isRedundantDHCPRoute(candidate, &defaultRoute) {
				t.Fatalf("mismatched route was treated as redundant: candidate=%#v default=%#v", candidate, defaultRoute)
			}
		})
	}
}

func TestIsGatewayHostRoute(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		gateway     string
		want        bool
	}{
		{name: "bare IPv4", destination: "10.0.0.1", gateway: "10.0.0.1", want: true},
		{name: "IPv4 host prefix", destination: "10.0.0.1/32", gateway: "10.0.0.1", want: true},
		{name: "bare IPv6", destination: "2001:db8::1", gateway: "2001:db8::1", want: true},
		{name: "IPv6 host prefix", destination: "2001:db8::1/128", gateway: "2001:db8::1", want: true},
		{name: "zoned IPv6 gateway", destination: "fe80::1", gateway: "fe80::1%ens3", want: true},
		{name: "non-host prefix", destination: "10.0.0.0/24", gateway: "10.0.0.1", want: false},
		{name: "different host", destination: "10.0.0.2", gateway: "10.0.0.1", want: false},
		{name: "invalid destination", destination: "not-an-address", gateway: "10.0.0.1", want: false},
		{name: "invalid gateway", destination: "10.0.0.1", gateway: "not-an-address", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isGatewayHostRoute(test.destination, test.gateway); got != test.want {
				t.Fatalf("isGatewayHostRoute(%q, %q) = %t, want %t", test.destination, test.gateway, got, test.want)
			}
		})
	}
}

func TestSystemdLeaseMustMatchSelectedInterfaceIndex(t *testing.T) {
	root := t.TempDir()
	leaseDir := filepath.Join(root, "run", "systemd", "netif", "leases")
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaseDir, "3"), []byte("ADDRESS=192.0.2.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if evidence := inspectConfiguration(root, "ens3", 2, "02:00:00:00:00:01", nil); evidence.Lease4 {
		t.Fatalf("lease from another interface was accepted: %#v", evidence)
	}
	if err := os.WriteFile(filepath.Join(leaseDir, "2"), []byte("ADDRESS=192.0.2.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if evidence := inspectConfiguration(root, "ens3", 2, "02:00:00:00:00:01", nil); !evidence.Lease4 {
		t.Fatalf("selected interface lease was not accepted: %#v", evidence)
	}
}

func TestRouterOSDualStackAndScopedDNS(t *testing.T) {
	plan := model.NetworkPlan{
		InterfaceName: "ens3",
		MAC:           "02:00:00:00:00:01",
		MTU:           1400,
		IPv4:          model.IPv4Plan{Mode: "dhcp", UsePeerDNS: false},
		IPv6: model.IPv6Plan{
			SLAAC:      true,
			DHCP:       true,
			Addresses:  []string{"2001:db8::10/64"},
			UsePeerDNS: true,
		},
		DNS: []string{"2001:4860:4860::8888", "fe80::53%ens3"},
	}
	script, err := RouterOSScript(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"accept-router-advertisements=yes",
		"request=address add-default-route=yes use-peer-dns=yes",
		"address=2001:db8::10/64",
		`"fe80::53%" . $uplinkName`,
		"/ip/dns/set servers=$dnsServers",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("script does not contain %q:\n%s", expected, script)
		}
	}
}
