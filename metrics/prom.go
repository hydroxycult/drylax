package metrics
import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)
var (
	PasteCreated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "drylax_paste_created_total",
		Help: "no. of pastes created",
	})
	PasteRetrieved = promauto.NewCounter(prometheus.CounterOpts{
		Name: "drylax_paste_retrieved_total",
		Help: "no. of pastes retrieved",
	})
	CacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "drylax_cache_hits_total",
		Help: "no. of cache hits",
	})
	CacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "drylax_cache_misses_total",
		Help: "no. of cache misses",
	})
	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "drylax_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint", "status"},
	)
	RateLimitHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "drylax_rate_limit_hits_total",
			Help: "no. of rate limit violations",
		},
		[]string{"endpoint"},
	)
	PruneCycles = promauto.NewCounter(prometheus.CounterOpts{
		Name: "drylax_prune_cycles_total",
		Help: "no. of cleanup worker cycles",
	})
	EncryptionOps = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "drylax_encryption_operations_total",
			Help: "no. of encryption/decryption operations",
		},
		[]string{"operation"},
	)
	RecentErrorRatePercent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "drylax_recent_error_rate_percent",
		Help: "5min rolling avg error rate percentage",
	})
)
func Init() {
}
