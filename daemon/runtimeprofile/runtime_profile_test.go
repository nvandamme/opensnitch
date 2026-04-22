package runtimeprofile

import (
	"bufio"
	"context"
	"fmt"
	"math"
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

type kernelPressureMetrics struct {
	durationSecs         uint64
	floodTasks           int
	enqueueTimeoutUs     uint64
	attemptedTotal       uint64
	enqueuedTotal        uint64
	enqueueTimeoutsTotal uint64
	enqueueClosedTotal   uint64
	forcedKernelAbort    bool
	attemptedPPS         float64
	enqueuedPPS          float64
	enqueueDropRatio     float64
	dropDelta            stressDropSnapshot
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
	started := time.Now()
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

	fmt.Printf(
		"mixed-saturation backend=go verdict_ms=%.3f\n",
		time.Since(started).Seconds()*1000.0,
	)
}

func TestStressProfileReportsConnectLatencyAndPipelineDrops(t *testing.T) {
	enforceHarnessGoLogLevel(t)

	if os.Getenv("OPENSNITCH_STRESS_PROFILE") == "" {
		t.Skip("profiling harness; set OPENSNITCH_STRESS_PROFILE=1 to run")
	}

	rounds := 1_000
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
	startedAll := time.Now()

	for i := 0; i < rounds; i++ {
		requestID := baseRequestID + uint64(i)
		started := time.Now()

		// Mirror Rust harness fast path: non-blocking enqueue first,
		// then bounded blocking fallback.
		select {
		case h.connect <- stressConnectAttempt{requestID: requestID}:
		default:
			select {
			case h.connect <- stressConnectAttempt{requestID: requestID}:
			case <-time.After(2 * time.Second):
				t.Fatalf("connect enqueue timeout on round %d", i)
			}
		}

		// Mirror Rust harness fast path: non-blocking verdict read first,
		// then bounded blocking fallback.
		var verdict stressConnectVerdict
		select {
		case verdict = <-h.verdict:
		default:
			select {
			case verdict = <-h.verdict:
			case <-time.After(2 * time.Second):
				t.Fatalf("verdict timeout on round %d", i)
			}
		}
		if verdict.requestID != requestID {
			t.Fatalf("unexpected request id on round %d: got=%d want=%d", i, verdict.requestID, requestID)
		}
		if !verdict.allow || verdict.reject {
			t.Fatalf("unexpected verdict on round %d: %+v", i, verdict)
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
	totalElapsed := time.Since(startedAll)
	timeOpUs := totalElapsed.Seconds() * 1_000_000.0 / float64(rounds)
	opsS := float64(rounds) / totalElapsed.Seconds()
	throughputProduct := timeOpUs * opsS
	if math.IsNaN(timeOpUs) || math.IsInf(timeOpUs, 0) || math.IsNaN(opsS) || math.IsInf(opsS, 0) || math.IsNaN(throughputProduct) || math.IsInf(throughputProduct, 0) || math.Abs(throughputProduct-1_000_000.0) > 10_000.0 {
		t.Fatalf("invalid throughput conversion: time_op_us=%.6f ops_s=%.6f product=%.3f", timeOpUs, opsS, throughputProduct)
	}

	dropAfter := h.snapshotDrops()
	dropDelta := dropAfter.saturatingDelta(dropBefore)
	enforceGoStressRegressionGuard(t, p95, p99, max, dropDelta.total())

	fmt.Printf(
		"stress-profile backend=go rounds=%d p50_ms=%.3f p95_ms=%.3f p99_ms=%.3f max_ms=%.3f time_op_us=%.3f ops_s=%.1f drop_dns=%d drop_process=%d drop_firewall=%d drop_total=%d\n",
		rounds,
		p50.Seconds()*1000.0,
		p95.Seconds()*1000.0,
		p99.Seconds()*1000.0,
		max.Seconds()*1000.0,
		timeOpUs,
		opsS,
		dropDelta.dns,
		dropDelta.process,
		dropDelta.firewall,
		dropDelta.total(),
	)
}

func runKernelPressureProfile(durationSecs uint64, floodTasks int, enqueueMode string, enqueueTimeoutUs uint64) kernelPressureMetrics {
	if durationSecs < 1 {
		durationSecs = 1
	}
	if durationSecs > 30 {
		durationSecs = 30
	}
	if floodTasks < 1 {
		floodTasks = 1
	}
	if floodTasks > 32 {
		floodTasks = 32
	}
	if enqueueTimeoutUs < 10 {
		enqueueTimeoutUs = 10
	}
	if enqueueTimeoutUs > 20_000 {
		enqueueTimeoutUs = 20_000
	}

	h := newStressHarness()
	defer h.stop()

	var attempted uint64
	var enqueued uint64
	var enqueueTimeouts uint64
	var enqueueClosed uint64

	dropBefore := h.snapshotDrops()
	floodCtx, floodCancel := context.WithCancel(h.ctx)
	started := time.Now()

	var floodWG sync.WaitGroup
	for workerID := 0; workerID < floodTasks; workerID++ {
		workerID := workerID
		floodWG.Add(1)
		go func() {
			defer floodWG.Done()
			i := uint64(workerID)
			burstSize := 32
			consecutiveSaturation := 0

			for {
				select {
				case <-floodCtx.Done():
					return
				default:
				}

				batchSaturation := 0
				saturationDNSOrProc := 0

				for n := 0; n < burstSize; n++ {
					select {
					case <-floodCtx.Done():
						return
					default:
					}

					lane := i % 3
					evt := stressKernelEvent{pipeline: stressPipeline(lane)}
					atomic.AddUint64(&attempted, 1)
					saturated := false

					if enqueueMode == "timeout" {
						select {
						case <-floodCtx.Done():
							return
						case h.kernelCh <- evt:
							atomic.AddUint64(&enqueued, 1)
						case <-time.After(time.Duration(enqueueTimeoutUs) * time.Microsecond):
							atomic.AddUint64(&enqueueTimeouts, 1)
							saturated = true
						}
					} else {
						select {
						case <-floodCtx.Done():
							return
						case h.kernelCh <- evt:
							atomic.AddUint64(&enqueued, 1)
						default:
							saturated = true
						}
					}

					if saturated {
						batchSaturation++
						if lane != 2 {
							saturationDNSOrProc++
						}
					}

					i++
				}

				if batchSaturation > 0 {
					consecutiveSaturation++
					if burstSize/2 > 4 {
						burstSize /= 2
					} else {
						burstSize = 4
					}

					if consecutiveSaturation >= 2 {
						backoffUs := 100
						if saturationDNSOrProc > (batchSaturation / 2) {
							backoffUs = 250
						}
						select {
						case <-floodCtx.Done():
							return
						case <-time.After(time.Duration(backoffUs) * time.Microsecond):
						}
					}
				} else {
					consecutiveSaturation = 0
					if burstSize+4 < 128 {
						burstSize += 4
					} else {
						burstSize = 128
					}
				}

				if (i & 0x3FF) == 0 {
					runtime.Gosched()
				}
			}
		}()
	}

	time.Sleep(time.Duration(durationSecs) * time.Second)
	floodCancel()
	floodWG.Wait()
	time.Sleep(250 * time.Millisecond)

	elapsed := time.Since(started)
	attemptedTotal := atomic.LoadUint64(&attempted)
	enqueuedTotal := atomic.LoadUint64(&enqueued)
	enqueueTimeoutsTotal := atomic.LoadUint64(&enqueueTimeouts)
	enqueueClosedTotal := atomic.LoadUint64(&enqueueClosed)

	dropAfter := h.snapshotDrops()
	dropDelta := dropAfter.saturatingDelta(dropBefore)

	attemptedPPS := 0.0
	enqueuedPPS := 0.0
	if elapsed.Seconds() > 0 {
		attemptedPPS = float64(attemptedTotal) / elapsed.Seconds()
		enqueuedPPS = float64(enqueuedTotal) / elapsed.Seconds()
	}

	enqueueDropRatio := 0.0
	if attemptedTotal > 0 {
		enqueueDropRatio = float64(attemptedTotal-enqueuedTotal) / float64(attemptedTotal)
	}

	return kernelPressureMetrics{
		durationSecs:         durationSecs,
		floodTasks:           floodTasks,
		enqueueTimeoutUs:     enqueueTimeoutUs,
		attemptedTotal:       attemptedTotal,
		enqueuedTotal:        enqueuedTotal,
		enqueueTimeoutsTotal: enqueueTimeoutsTotal,
		enqueueClosedTotal:   enqueueClosedTotal,
		forcedKernelAbort:    false,
		attemptedPPS:         attemptedPPS,
		enqueuedPPS:          enqueuedPPS,
		enqueueDropRatio:     enqueueDropRatio,
		dropDelta:            dropDelta,
	}
}

func TestStressProfileReportsKernelPipelinePressure(t *testing.T) {
	enforceHarnessGoLogLevel(t)

	if os.Getenv("OPENSNITCH_STRESS_PROFILE") == "" {
		t.Skip("profiling harness; set OPENSNITCH_STRESS_PROFILE=1 to run")
	}

	durationSecs := uint64(3)
	if raw := os.Getenv("OPENSNITCH_KERNEL_PRESSURE_SECS"); raw != "" {
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			durationSecs = parsed
		}
	}

	floodTasks := 4
	if raw := os.Getenv("OPENSNITCH_KERNEL_PRESSURE_TASKS"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			floodTasks = parsed
		}
	}

	enqueueMode := os.Getenv("OPENSNITCH_KERNEL_PRESSURE_ENQUEUE_MODE")
	if enqueueMode == "" {
		enqueueMode = "try"
	}

	enqueueTimeoutUs := uint64(200)
	if raw := os.Getenv("OPENSNITCH_KERNEL_PRESSURE_ENQUEUE_TIMEOUT_US"); raw != "" {
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			enqueueTimeoutUs = parsed
		}
	}

	metrics := runKernelPressureProfile(durationSecs, floodTasks, enqueueMode, enqueueTimeoutUs)

	fmt.Printf(
		"kernel-pressure mode=%s enqueue_timeout_us=%d secs=%d flood_tasks=%d attempted=%d enqueued=%d enqueue_timeouts=%d enqueue_closed=%d forced_kernel_abort=%v attempted_pps=%.0f enqueued_pps=%.0f enqueue_drop_ratio=%.4f pipeline_drop_dns=%d pipeline_drop_process=%d pipeline_drop_firewall=%d pipeline_drop_total=%d\n",
		enqueueMode,
		metrics.enqueueTimeoutUs,
		metrics.durationSecs,
		metrics.floodTasks,
		metrics.attemptedTotal,
		metrics.enqueuedTotal,
		metrics.enqueueTimeoutsTotal,
		metrics.enqueueClosedTotal,
		metrics.forcedKernelAbort,
		metrics.attemptedPPS,
		metrics.enqueuedPPS,
		metrics.enqueueDropRatio,
		metrics.dropDelta.dns,
		metrics.dropDelta.process,
		metrics.dropDelta.firewall,
		metrics.dropDelta.total(),
	)

	if metrics.enqueuedTotal == 0 {
		t.Fatal("kernel pressure run did not enqueue events")
	}
}

func TestStressProfileReportsKernelPipelineTimeoutSweep(t *testing.T) {
	enforceHarnessGoLogLevel(t)

	if os.Getenv("OPENSNITCH_STRESS_PROFILE") == "" {
		t.Skip("profiling harness; set OPENSNITCH_STRESS_PROFILE=1 to run")
	}

	durationSecs := uint64(2)
	if raw := os.Getenv("OPENSNITCH_KERNEL_PRESSURE_SWEEP_SECS"); raw != "" {
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			durationSecs = parsed
		}
	}

	floodTasks := 4
	if raw := os.Getenv("OPENSNITCH_KERNEL_PRESSURE_SWEEP_TASKS"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			floodTasks = parsed
		}
	}

	sweepRaw := os.Getenv("OPENSNITCH_KERNEL_PRESSURE_SWEEP_US")
	if sweepRaw == "" {
		sweepRaw = "50,100,200,500,1000"
	}

	timeouts := make([]uint64, 0)
	for _, token := range strings.Split(sweepRaw, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if value, err := strconv.ParseUint(token, 10, 64); err == nil {
			timeouts = append(timeouts, value)
		}
	}
	if len(timeouts) == 0 {
		timeouts = append(timeouts, 50, 100, 200, 500, 1000)
	}

	fmt.Println("kernel-pressure-sweep-csv-header,timeout_us,secs,flood_tasks,attempted,enqueued,enqueue_timeouts,enqueue_closed,forced_kernel_abort,attempted_pps,enqueued_pps,enqueue_drop_ratio,pipeline_drop_dns,pipeline_drop_process,pipeline_drop_firewall,pipeline_drop_total")

	results := make([]kernelPressureMetrics, 0, len(timeouts))
	for _, timeoutUs := range timeouts {
		metrics := runKernelPressureProfile(durationSecs, floodTasks, "timeout", timeoutUs)

		fmt.Printf(
			"kernel-pressure-sweep timeout_us=%d secs=%d flood_tasks=%d attempted=%d enqueued=%d enqueue_timeouts=%d enqueue_closed=%d forced_kernel_abort=%v attempted_pps=%.0f enqueued_pps=%.0f enqueue_drop_ratio=%.4f pipeline_drop_total=%d\n",
			metrics.enqueueTimeoutUs,
			metrics.durationSecs,
			metrics.floodTasks,
			metrics.attemptedTotal,
			metrics.enqueuedTotal,
			metrics.enqueueTimeoutsTotal,
			metrics.enqueueClosedTotal,
			metrics.forcedKernelAbort,
			metrics.attemptedPPS,
			metrics.enqueuedPPS,
			metrics.enqueueDropRatio,
			metrics.dropDelta.total(),
		)

		fmt.Printf(
			"kernel-pressure-sweep-csv,%d,%d,%d,%d,%d,%d,%d,%v,%.0f,%.0f,%.4f,%d,%d,%d,%d\n",
			metrics.enqueueTimeoutUs,
			metrics.durationSecs,
			metrics.floodTasks,
			metrics.attemptedTotal,
			metrics.enqueuedTotal,
			metrics.enqueueTimeoutsTotal,
			metrics.enqueueClosedTotal,
			metrics.forcedKernelAbort,
			metrics.attemptedPPS,
			metrics.enqueuedPPS,
			metrics.enqueueDropRatio,
			metrics.dropDelta.dns,
			metrics.dropDelta.process,
			metrics.dropDelta.firewall,
			metrics.dropDelta.total(),
		)

		if metrics.enqueuedTotal == 0 {
			t.Fatalf("timeout_us=%d did not enqueue events", metrics.enqueueTimeoutUs)
		}
		results = append(results, metrics)
	}

	hasNonAbort := false
	for _, m := range results {
		if !m.forcedKernelAbort {
			hasNonAbort = true
			break
		}
	}

	bestScore := math.Inf(-1)
	var best *kernelPressureMetrics
	for i := range results {
		m := &results[i]
		if hasNonAbort && m.forcedKernelAbort {
			continue
		}

		score := m.enqueuedPPS * (1.0 - m.enqueueDropRatio)
		replace := false
		if score > bestScore {
			replace = true
		} else if math.Abs(score-bestScore) < 1e-9 && best != nil {
			if m.enqueueDropRatio < best.enqueueDropRatio || (math.Abs(m.enqueueDropRatio-best.enqueueDropRatio) < 1e-9 && m.enqueueTimeoutUs < best.enqueueTimeoutUs) {
				replace = true
			}
		}

		if best == nil || replace {
			best = m
			bestScore = score
		}
	}

	if best != nil {
		fmt.Printf(
			"kernel-pressure-sweep-recommend timeout_us=%d score=%.0f enqueued_pps=%.0f enqueue_drop_ratio=%.4f pipeline_drop_total=%d forced_kernel_abort=%v\n",
			best.enqueueTimeoutUs,
			bestScore,
			best.enqueuedPPS,
			best.enqueueDropRatio,
			best.dropDelta.total(),
			best.forcedKernelAbort,
		)
	}
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
