package runtimeprofile

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	oslog "github.com/evilsocket/opensnitch/daemon/log"
)

const (
	stressKernelPipelineSendRetries = 8
	stressKernelPipelineSendBackoff = 10 * time.Millisecond
)

type stressPipeline uint8

const (
	stressPipelineDNS stressPipeline = iota
	stressPipelineProcess
	stressPipelineFirewall
)

type stressKernelEvent struct {
	pipeline stressPipeline
}

type stressConnectAttempt struct {
	requestID uint64
}

type stressConnectVerdict struct {
	requestID uint64
	allow     bool
	reject    bool
}

type stressDropCounters struct {
	dns      atomic.Uint64
	process  atomic.Uint64
	firewall atomic.Uint64
}

type stressDropSnapshot struct {
	dns      uint64
	process  uint64
	firewall uint64
}

func (s stressDropSnapshot) total() uint64 {
	return s.dns + s.process + s.firewall
}

func (s stressDropSnapshot) saturatingDelta(before stressDropSnapshot) stressDropSnapshot {
	return stressDropSnapshot{
		dns:      saturatingSub(s.dns, before.dns),
		process:  saturatingSub(s.process, before.process),
		firewall: saturatingSub(s.firewall, before.firewall),
	}
}

func saturatingSub(after, before uint64) uint64 {
	if after <= before {
		return 0
	}
	return after - before
}

type stressHarness struct {
	ctx      context.Context
	cancel   context.CancelFunc
	kernelCh chan stressKernelEvent
	connect  chan stressConnectAttempt
	verdict  chan stressConnectVerdict
	drops    stressDropCounters
	wg       sync.WaitGroup
}

func newStressHarness() *stressHarness {
	ctx, cancel := context.WithCancel(context.Background())
	h := &stressHarness{
		ctx:      ctx,
		cancel:   cancel,
		kernelCh: make(chan stressKernelEvent, 256),
		connect:  make(chan stressConnectAttempt, 256),
		verdict:  make(chan stressConnectVerdict, 256),
	}

	dnsCh := make(chan struct{}, 32)
	processCh := make(chan struct{}, 32)
	firewallCh := make(chan struct{}, 32)

	h.startPipelineWorker(dnsCh, 2*time.Millisecond)
	h.startPipelineWorker(processCh, 2*time.Millisecond)
	h.startPipelineWorker(firewallCh, 2*time.Millisecond)
	h.startConnectWorker()
	h.startRouter(dnsCh, processCh, firewallCh)

	return h
}

func (h *stressHarness) startPipelineWorker(ch <-chan struct{}, delay time.Duration) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			select {
			case <-h.ctx.Done():
				return
			case <-ch:
				select {
				case <-h.ctx.Done():
					return
				case <-time.After(delay):
				}
			}
		}
	}()
}

func (h *stressHarness) startConnectWorker() {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			select {
			case <-h.ctx.Done():
				return
			case req := <-h.connect:
				select {
				case <-h.ctx.Done():
					return
				case h.verdict <- stressConnectVerdict{requestID: req.requestID, allow: true, reject: false}:
				}
			}
		}
	}()
}

func (h *stressHarness) startRouter(dnsCh, processCh, firewallCh chan<- struct{}) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			select {
			case <-h.ctx.Done():
				return
			case evt := <-h.kernelCh:
				switch evt.pipeline {
				case stressPipelineDNS:
					if !dispatchStressPipelineEvent(h.ctx, dnsCh, struct{}{}, &h.drops.dns) {
						return
					}
				case stressPipelineProcess:
					if !dispatchStressPipelineEvent(h.ctx, processCh, struct{}{}, &h.drops.process) {
						return
					}
				case stressPipelineFirewall:
					if !dispatchStressPipelineEvent(h.ctx, firewallCh, struct{}{}, &h.drops.firewall) {
						return
					}
				}
			}
		}
	}()
}

func dispatchStressPipelineEvent[T any](
	ctx context.Context,
	tx chan<- T,
	event T,
	dropCounter *atomic.Uint64,
) bool {
	for i := 0; i < stressKernelPipelineSendRetries; i++ {
		select {
		case <-ctx.Done():
			return false
		case tx <- event:
			return true
		default:
		}

		select {
		case <-ctx.Done():
			return false
		case <-time.After(stressKernelPipelineSendBackoff):
		}
	}

	dropCounter.Add(1)
	return true
}

func (h *stressHarness) snapshotDrops() stressDropSnapshot {
	return stressDropSnapshot{
		dns:      h.drops.dns.Load(),
		process:  h.drops.process.Load(),
		firewall: h.drops.firewall.Load(),
	}
}

func (h *stressHarness) stop() {
	h.cancel()
	h.wg.Wait()
}

func durationPercentile(sorted []time.Duration, pct float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	maxIdx := len(sorted) - 1
	idx := int(float64(maxIdx)*pct + 0.5)
	if idx > maxIdx {
		idx = maxIdx
	}
	return sorted[idx]
}

type stressPerfBaseline struct {
	p95Ms     float64
	p99Ms     float64
	maxMs     float64
	dropTotal uint64
}

func stressTodoPath() string {
	if path := os.Getenv("OPENSNITCH_STRESS_TODO_PATH"); path != "" {
		return path
	}
	return "../../daemon-rs/TODO.md"
}

func parseTodoString(todo string, key string) (string, bool) {
	scanner := bufio.NewScanner(strings.NewReader(todo))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if value, ok := strings.CutPrefix(line, key); ok {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

func parseTodoFloat(todo string, key string) (float64, bool) {
	raw, ok := parseTodoString(todo, key)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func parseTodoUint(todo string, key string) (uint64, bool) {
	raw, ok := parseTodoString(todo, key)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func loadGoStressBaseline(todo string) (stressPerfBaseline, bool) {
	p95, ok := parseTodoFloat(todo, "PERF_BASELINE_GO_P95_MS=")
	if !ok {
		return stressPerfBaseline{}, false
	}
	p99, ok := parseTodoFloat(todo, "PERF_BASELINE_GO_P99_MS=")
	if !ok {
		return stressPerfBaseline{}, false
	}
	mx, ok := parseTodoFloat(todo, "PERF_BASELINE_GO_MAX_MS=")
	if !ok {
		return stressPerfBaseline{}, false
	}
	drop, ok := parseTodoUint(todo, "PERF_BASELINE_GO_DROP_TOTAL=")
	if !ok {
		return stressPerfBaseline{}, false
	}

	return stressPerfBaseline{
		p95Ms:     p95,
		p99Ms:     p99,
		maxMs:     mx,
		dropTotal: drop,
	}, true
}

func isClearRegression(observedMs float64, baselineMs float64, factor float64, minDeltaMs float64) bool {
	return observedMs > baselineMs*factor && (observedMs-baselineMs) > minDeltaMs
}

func enforceGoStressRegressionGuard(t *testing.T, p95, p99, max time.Duration, dropTotal uint64) {
	t.Helper()

	if os.Getenv("OPENSNITCH_STRESS_SKIP_REGRESSION_CHECK") == "1" {
		return
	}

	todoPath := stressTodoPath()
	todoBytes, err := os.ReadFile(todoPath)
	if err != nil {
		t.Fatalf("failed to read TODO baseline file %q: %v", todoPath, err)
	}
	todo := string(todoBytes)

	baseline, ok := loadGoStressBaseline(todo)
	if !ok {
		t.Fatalf("missing GO stress baseline keys in TODO baseline file %q", todoPath)
	}

	factor, ok := parseTodoFloat(todo, "PERF_CLEAR_REGRESSION_FACTOR=")
	if !ok {
		factor = 1.75
	}

	minDeltaMs, ok := parseTodoFloat(todo, "PERF_CLEAR_REGRESSION_MIN_DELTA_MS=")
	if !ok {
		minDeltaMs = 0.050
	}

	p95Ms := p95.Seconds() * 1000.0
	p99Ms := p99.Seconds() * 1000.0
	maxMs := max.Seconds() * 1000.0

	regressions := make([]string, 0, 4)

	if isClearRegression(p95Ms, baseline.p95Ms, factor, minDeltaMs) {
		regressions = append(regressions, fmt.Sprintf("p95_ms observed=%.3f baseline=%.3f", p95Ms, baseline.p95Ms))
	}

	if isClearRegression(p99Ms, baseline.p99Ms, factor, minDeltaMs) {
		regressions = append(regressions, fmt.Sprintf("p99_ms observed=%.3f baseline=%.3f", p99Ms, baseline.p99Ms))
	}

	if isClearRegression(maxMs, baseline.maxMs, factor, minDeltaMs) {
		regressions = append(regressions, fmt.Sprintf("max_ms observed=%.3f baseline=%.3f", maxMs, baseline.maxMs))
	}

	if dropTotal > baseline.dropTotal {
		regressions = append(regressions, fmt.Sprintf("drop_total observed=%d baseline=%d", dropTotal, baseline.dropTotal))
	}

	if len(regressions) > 0 {
		t.Fatalf(
			"stress-profile clear regression detected (factor=%.2f, min_delta_ms=%.3f): %s",
			factor,
			minDeltaMs,
			strings.Join(regressions, "; "),
		)
	}
}

func TestConnectAttemptProgressesUnderMixedNonConnectSaturation(t *testing.T) {
	enforceHarnessGoLogLevel(t)

	h := newStressHarness()
	defer h.stop()

	const nonConnectEvents = 10_000
	for i := 0; i < nonConnectEvents; i++ {
		evt := stressKernelEvent{pipeline: stressPipeline(i % 3)}
		select {
		case h.kernelCh <- evt:
		default:
		}
	}

	requestID := uint64(0xC0FFEE)
	select {
	case h.connect <- stressConnectAttempt{requestID: requestID}:
	case <-time.After(2 * time.Second):
		t.Fatal("connect attempt enqueue timeout")
	}

	select {
	case verdict := <-h.verdict:
		if verdict.requestID != requestID {
			t.Fatalf("unexpected request id: got=%d want=%d", verdict.requestID, requestID)
		}
		if !verdict.allow || verdict.reject {
			t.Fatalf("unexpected verdict: %+v", verdict)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("verdict timeout")
	}
}

func TestStressProfileReportsConnectLatencyAndPipelineDrops(t *testing.T) {
	enforceHarnessGoLogLevel(t)

	if os.Getenv("OPENSNITCH_STRESS_PROFILE") == "" {
		t.Skip("profiling harness; set OPENSNITCH_STRESS_PROFILE=1 to run")
	}

	rounds := 2_000
	if raw := os.Getenv("OPENSNITCH_STRESS_ROUNDS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			t.Fatalf("invalid OPENSNITCH_STRESS_ROUNDS value %q", raw)
		}
		rounds = parsed
	}

	h := newStressHarness()
	defer h.stop()

	floodDone := make(chan struct{})
	go func() {
		defer close(floodDone)
		for i := 0; ; i++ {
			select {
			case <-h.ctx.Done():
				return
			default:
			}

			evt := stressKernelEvent{pipeline: stressPipeline(i % 3)}
			select {
			case <-h.ctx.Done():
				return
			case h.kernelCh <- evt:
			default:
			}
			runtime.Gosched()
		}
	}()

	dropBefore := h.snapshotDrops()
	latencies := make([]time.Duration, 0, rounds)
	baseRequestID := uint64(0xD00D_0000)

	for i := 0; i < rounds; i++ {
		requestID := baseRequestID + uint64(i)
		started := time.Now()

		select {
		case h.connect <- stressConnectAttempt{requestID: requestID}:
		case <-time.After(2 * time.Second):
			t.Fatalf("connect enqueue timeout on round %d", i)
		}

		select {
		case verdict := <-h.verdict:
			if verdict.requestID != requestID {
				t.Fatalf("unexpected request id on round %d: got=%d want=%d", i, verdict.requestID, requestID)
			}
			if !verdict.allow || verdict.reject {
				t.Fatalf("unexpected verdict on round %d: %+v", i, verdict)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("verdict timeout on round %d", i)
		}

		latencies = append(latencies, time.Since(started))
	}

	h.cancel()
	<-floodDone

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	p50 := durationPercentile(latencies, 0.50)
	p95 := durationPercentile(latencies, 0.95)
	p99 := durationPercentile(latencies, 0.99)
	max := time.Duration(0)
	if len(latencies) > 0 {
		max = latencies[len(latencies)-1]
	}

	dropAfter := h.snapshotDrops()
	dropDelta := dropAfter.saturatingDelta(dropBefore)
	enforceGoStressRegressionGuard(t, p95, p99, max, dropDelta.total())

	fmt.Printf(
		"stress-profile backend=go rounds=%d p50_ms=%.3f p95_ms=%.3f p99_ms=%.3f max_ms=%.3f drop_dns=%d drop_process=%d drop_firewall=%d drop_total=%d\n",
		rounds,
		p50.Seconds()*1000.0,
		p95.Seconds()*1000.0,
		p99.Seconds()*1000.0,
		max.Seconds()*1000.0,
		dropDelta.dns,
		dropDelta.process,
		dropDelta.firewall,
		dropDelta.total(),
	)
}

func enforceHarnessGoLogLevel(t *testing.T) {
	t.Helper()

	raw := strings.TrimSpace(os.Getenv("OPENSNITCH_HARNESS_GO_LOG_LEVEL"))
	normalized := strings.ToLower(raw)
	if normalized != "err" && normalized != "error" {
		t.Fatalf(
			"go harness tests require OPENSNITCH_HARNESS_GO_LOG_LEVEL=err|error (current=%q)",
			raw,
		)
	}

	// Keep Go harness logging noise aligned with Rust perf/harness policy.
	oslog.SetLogLevel(oslog.ERROR)
}
