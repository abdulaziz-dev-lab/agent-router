// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// DIAGNOSTIC - fork only, not for upstream.
//
// TestDiagPortProbe measures how often each way of picking "free" ports returns a port that
// then fails to bind on all interfaces, and dumps whatever holds the port when that happens.

package internaltesting

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const diagMaxHolderDumps = 40

type diagPicker struct {
	name string
	pick func(t testing.TB, count int) []int
}

type diagResult struct {
	picked, dualFails, v4Fails  int
	minPort, maxPort, firstPort int
	failedPorts                 []int
}

func TestDiagPortProbe(t *testing.T) {
	if os.Getenv("PORT_PROBE_DIAG") == "" {
		t.Skip("set PORT_PROBE_DIAG=1 to run")
	}
	label := os.Getenv("PORT_PROBE_LABEL")
	rounds := diagEnvInt("PORT_PROBE_ROUNDS", 3)
	portsPerRound := diagEnvInt("PORT_PROBE_PORTS", 15000)

	diagLogSystem(t)

	pickers := []diagPicker{
		{name: "old 127.0.0.1:0", pick: diagOldRequireRandomPorts},
		{name: "wildcard :0", pick: diagWildcardRequireRandomPorts},
		{name: "new RequireRandomPorts", pick: RequireRandomPorts},
	}
	dumps := 0
	for round := range rounds {
		for _, p := range pickers {
			res := diagRunProbe(t, p, portsPerRound, &dumps)
			t.Logf("SUMMARY label=%s round=%d picker=%q picked=%d dual-stack-fails=%d tcp4-fails=%d first=%d min=%d max=%d failed=%v",
				label, round, p.name, res.picked, res.dualFails, res.v4Fails, res.firstPort, res.minPort, res.maxPort, res.failedPorts)
		}
		if round < rounds-1 {
			time.Sleep(30 * time.Second)
		}
	}
}

// diagOldRequireRandomPorts is RequireRandomPorts before the fix.
func diagOldRequireRandomPorts(t testing.TB, count int) []int {
	return diagEphemeralPorts(t, count, "127.0.0.1:0")
}

// diagWildcardRequireRandomPorts is the one-line alternative fix: probe ":0" instead.
func diagWildcardRequireRandomPorts(t testing.TB, count int) []int {
	return diagEphemeralPorts(t, count, ":0")
}

func diagEphemeralPorts(t testing.TB, count int, address string) []int {
	t.Helper()
	ports := make([]int, count)
	var listeners []net.Listener
	for i := range count {
		lc := net.ListenConfig{}
		lis, err := lc.Listen(context.Background(), "tcp", address)
		require.NoError(t, err)
		listeners = append(listeners, lis)
		ports[i] = lis.Addr().(*net.TCPAddr).Port
	}
	for _, lis := range listeners {
		require.NoError(t, lis.Close())
	}
	return ports
}

func diagRunProbe(t *testing.T, p diagPicker, portsPerRound int, dumps *int) diagResult {
	res := diagResult{minPort: 1 << 16}
	for res.picked < portsPerRound {
		for _, port := range p.pick(t, 6) {
			if res.picked == 0 {
				res.firstPort = port
			}
			res.picked++
			res.minPort = min(res.minPort, port)
			res.maxPort = max(res.maxPort, port)

			dualErr := diagTryListen("tcp", fmt.Sprintf(":%d", port))
			v4Err := diagTryListen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
			if dualErr == nil && v4Err == nil {
				continue
			}
			if dualErr != nil {
				res.dualFails++
			}
			if v4Err != nil {
				res.v4Fails++
			}
			res.failedPorts = append(res.failedPorts, port)
			t.Logf("COLLISION picker=%q port=%d dual-stack=%v tcp4=%v", p.name, port, dualErr, v4Err)
			if *dumps < diagMaxHolderDumps {
				*dumps++
				diagDumpHolder(t, port)
			}
		}
	}
	return res
}

func diagTryListen(network, address string) error {
	lc := net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		return err
	}
	return lis.Close()
}

func diagLogSystem(t *testing.T) {
	t.Logf("GOOS=%s GOARCH=%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "darwin" {
		diagLogCmd(t, "", "sw_vers")
		diagLogCmd(t, "", "sysctl", "net.inet.ip.portrange.first", "net.inet.ip.portrange.last",
			"net.inet.ip.portrange.hifirst", "net.inet.ip.portrange.hilast")
		diagLogCmd(t, "", "sysctl", "net.inet.tcp.randomize_ports")
		diagLogCmd(t, "", "sudo", "-n", "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
		diagLogCmd(t, "", "sudo", "-n", "skywalkctl", "flow")
	} else {
		diagLogCmd(t, "", "cat", "/proc/sys/net/ipv4/ip_local_port_range")
		diagLogCmd(t, "", "sudo", "-n", "ss", "-tlnp")
	}
}

func diagDumpHolder(t *testing.T, port int) {
	match := fmt.Sprintf(`[.:]%d\b`, port)
	diagLogCmd(t, "", "sudo", "-n", "lsof", "-nP", fmt.Sprintf("-iTCP:%d", port))
	if runtime.GOOS == "darwin" {
		diagLogCmd(t, match, "sudo", "-n", "netstat", "-anv", "-p", "tcp")
		diagLogCmd(t, match, "sudo", "-n", "skywalkctl", "flow")
	} else {
		diagLogCmd(t, match, "sudo", "-n", "ss", "-tanpe")
	}
}

// diagLogCmd logs the command output, keeping only lines matching filter when it is set.
func diagLogCmd(t *testing.T, filter string, name string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- diagnostic only.
	var re *regexp.Regexp
	if filter != "" {
		re = regexp.MustCompile(filter)
	}
	const maxLines = 300
	var kept []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if re == nil || re.MatchString(line) {
			kept = append(kept, line)
		}
	}
	if len(kept) > maxLines {
		kept = append(kept[:maxLines], fmt.Sprintf("... (%d more lines)", len(kept)-maxLines))
	}
	t.Logf("$ %s %s (err=%v, %d lines total)\n%s", name, strings.Join(args, " "), err, len(lines), strings.Join(kept, "\n"))
}

func diagEnvInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return def
}
