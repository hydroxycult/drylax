package lim

import (
	"drylax/metrics"
	"drylax/svc/util"
	"sync"
	"time"
)

type AnomalyDetector struct {
	mu           sync.Mutex
	window       []bucket
	windowSize   int
	currentIndex int
	onAnomaly    func()
	done         chan struct{}
}
type bucket struct {
	requests int64
	errors   int64
}

func NewAnomalyDetector(onAnomaly func()) *AnomalyDetector {
	return &AnomalyDetector{
		window:     make([]bucket, 5),
		windowSize: 5,
		onAnomaly:  onAnomaly,
		done:       make(chan struct{}),
	}
}
func (d *AnomalyDetector) Start() {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for {
			select {
			case <-ticker.C:
				d.AdvanceWindow()
			case <-d.done:
				ticker.Stop()
				return
			}
		}
	}()
}
func (d *AnomalyDetector) Stop() {
	close(d.done)
}
func (d *AnomalyDetector) RecordRequest() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.window[d.currentIndex].requests++
}
func (d *AnomalyDetector) RecordError() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.window[d.currentIndex].errors++
}
func (d *AnomalyDetector) AdvanceWindow() {
	d.mu.Lock()
	defer d.mu.Unlock()
	var totalReqs, totalErrs int64
	for _, b := range d.window {
		totalReqs += b.requests
		totalErrs += b.errors
	}
	var errorRate float64
	if totalReqs > 0 {
		errorRate = (float64(totalErrs) / float64(totalReqs)) * 100.0
	}
	metrics.RecentErrorRatePercent.Set(errorRate)
	if totalReqs > 10 && errorRate > 5.0 {
		util.Warn().
			Float64("error_rate", errorRate).
			Int64("total_reqs", totalReqs).
			Int64("total_errs", totalErrs).
			Msg("Anomaly detected: High error rate. Triggering adaptive rate limit.")
		if d.onAnomaly != nil {
			d.onAnomaly()
		}
	}
	d.currentIndex = (d.currentIndex + 1) % d.windowSize
	d.window[d.currentIndex] = bucket{}
}
