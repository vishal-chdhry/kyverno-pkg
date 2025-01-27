package metrics

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var (
	fqNameRegex         = regexp.MustCompile(`fqName: "([^"]+)"`)
	helpRegex           = regexp.MustCompile(`help: "([^"]+)"`)
	variableLabelsRegex = regexp.MustCompile(`variableLabels: {([^}]*)}`)
	constLabelsRegex    = regexp.MustCompile(`constLabels: {([^}]*)}`)
	labelPairRegex      = regexp.MustCompile(`(\w+)="([^"]*)"`)
	metricNameRegex     = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
)

type CustomMetricsRegistry struct {
	registry       *prometheus.Registry
	renamedMetrics map[string]string
	mu             sync.RWMutex
}

func NewCustomMetricsRegistry() *CustomMetricsRegistry {
	return &CustomMetricsRegistry{
		registry:       prometheus.NewRegistry(),
		renamedMetrics: make(map[string]string),
	}
}

func (r *CustomMetricsRegistry) RenameMetric(original, new string) error {
	if !metricNameRegex.MatchString(new) {
		return fmt.Errorf("invalid metric name: %s", new)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.renamedMetrics[original] = new
	return nil
}

func (r *CustomMetricsRegistry) Register(c prometheus.Collector) error {
	if c == nil {
		return fmt.Errorf("cannot register nil collector")
	}

	if metric, ok := c.(prometheus.Metric); ok {
		desc := metric.Desc()
		if desc == nil {
			return fmt.Errorf("metric descriptor is nil")
		}

		originalName, _, _, _ := parseDesc(desc)
		r.mu.RLock()
		newName, exists := r.renamedMetrics[originalName]
		r.mu.RUnlock()

		if exists {
			wrapped := &renamedCollector{
				originalCollector: c,
				newName:           newName,
			}
			return r.registry.Register(wrapped)
		}
	}
	return r.registry.Register(c)
}

func (r *CustomMetricsRegistry) MustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		if err := r.Register(c); err != nil {
			panic(err)
		}
	}
}

func (r *CustomMetricsRegistry) Unregister(c prometheus.Collector) bool {
	return r.registry.Unregister(c)
}

func (r *CustomMetricsRegistry) Gather() ([]*dto.MetricFamily, error) {
	return r.registry.Gather()
}

func parseDesc(desc *prometheus.Desc) (name string, help string, variableLabels []string, constLabels map[string]string) {
	descStr := desc.String()

	if matches := fqNameRegex.FindStringSubmatch(descStr); len(matches) >= 2 {
		name = matches[1]
	}

	if matches := helpRegex.FindStringSubmatch(descStr); len(matches) >= 2 {
		help = matches[1]
	}

	if matches := variableLabelsRegex.FindStringSubmatch(descStr); len(matches) >= 2 {
		labels := strings.Split(matches[1], ",")
		variableLabels = make([]string, 0, len(labels))
		for _, label := range labels {
			label = strings.TrimSpace(label)
			if label != "" {
				// Remove constraint indicator if present
				if strings.HasPrefix(label, "c(") && strings.HasSuffix(label, ")") {
					label = label[2 : len(label)-1]
				}
				variableLabels = append(variableLabels, label)
			}
		}
	}

	constLabels = make(map[string]string)
	if matches := constLabelsRegex.FindStringSubmatch(descStr); len(matches) >= 2 {
		labelPairs := labelPairRegex.FindAllStringSubmatch(matches[1], -1)
		for _, pair := range labelPairs {
			if len(pair) >= 3 {
				constLabels[pair[1]] = pair[2]
			}
		}
	}

	return name, help, variableLabels, constLabels
}

type renamedCollector struct {
	originalCollector prometheus.Collector
	newName           string
}

func (rc *renamedCollector) Describe(ch chan<- *prometheus.Desc) {
	if ch == nil {
		return
	}

	tempCh := make(chan *prometheus.Desc, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		rc.originalCollector.Describe(tempCh)
		close(tempCh)
	}()

	for desc := range tempCh {
		if desc == nil {
			continue
		}

		_, help, variableLabels, constLabels := parseDesc(desc)

		newDesc := prometheus.NewDesc(
			rc.newName,
			help,
			variableLabels,
			constLabels,
		)
		ch <- newDesc
	}

	<-done
}

func (rc *renamedCollector) Collect(ch chan<- prometheus.Metric) {
	if ch == nil {
		return
	}

	metrics := make(chan prometheus.Metric, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		rc.originalCollector.Collect(metrics)
		close(metrics)
	}()

	for metric := range metrics {
		if metric == nil {
			continue
		}

		dtoMetric := &dto.Metric{}
		if err := metric.Write(dtoMetric); err != nil {
			continue
		}

		originalDesc := metric.Desc()
		if originalDesc == nil {
			continue
		}

		_, help, variableLabels, constLabels := parseDesc(originalDesc)

		newDesc := prometheus.NewDesc(
			rc.newName,
			help,
			variableLabels,
			constLabels,
		)

		labelValues := extractLabelValues(dtoMetric, variableLabels)
		value, metricType := getMetricValueAndType(dtoMetric)
		if value == nil {
			continue
		}

		newMetric, err := prometheus.NewConstMetric(
			newDesc,
			metricType,
			*value,
			labelValues...,
		)
		if err != nil {
			continue
		}

		ch <- newMetric
	}

	<-done
}

func extractLabelValues(dtoMetric *dto.Metric, labelNames []string) []string {
	if dtoMetric == nil {
		return nil
	}

	labelMap := make(map[string]string, len(dtoMetric.Label))
	for _, lp := range dtoMetric.Label {
		if lp != nil {
			labelMap[lp.GetName()] = lp.GetValue()
		}
	}

	values := make([]string, len(labelNames))
	for i, name := range labelNames {
		values[i] = labelMap[name]
	}
	return values
}

func getMetricValueAndType(dtoMetric *dto.Metric) (*float64, prometheus.ValueType) {
	if dtoMetric == nil {
		return nil, prometheus.UntypedValue
	}

	switch {
	case dtoMetric.Gauge != nil:
		return dtoMetric.Gauge.Value, prometheus.GaugeValue
	case dtoMetric.Counter != nil:
		return dtoMetric.Counter.Value, prometheus.CounterValue
	case dtoMetric.Untyped != nil:
		return dtoMetric.Untyped.Value, prometheus.UntypedValue
	case dtoMetric.Histogram != nil:
		return nil, prometheus.UntypedValue // not handled yet explicitly
	case dtoMetric.Summary != nil:
		return nil, prometheus.UntypedValue // not handled yet explicitly
	default:
		return nil, prometheus.UntypedValue
	}
}
