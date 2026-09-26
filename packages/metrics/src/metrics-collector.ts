export interface MetricLabels {
  [key: string]: string;
}

interface CounterState {
  type: 'counter';
  name: string;
  help: string;
  values: Map<string, number>;
}

interface GaugeState {
  type: 'gauge';
  name: string;
  help: string;
  values: Map<string, number>;
}

interface HistogramState {
  type: 'histogram';
  name: string;
  help: string;
  buckets: number[];
  observations: Map<string, number[]>;
}

type MetricState = CounterState | GaugeState | HistogramState;

function labelsToKey(labels: MetricLabels): string {
  const entries = Object.entries(labels).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) return '';
  return entries.map(([k, v]) => `${k}="${v}"`).join(',');
}

function formatLabels(key: string): string {
  return key ? `{${key}}` : '';
}

/**
 * Lightweight Prometheus-compatible metrics collector.
 * Provides counters, gauges, and histograms with label support.
 * Exports metrics in Prometheus text exposition format.
 */
export class MetricsCollector {
  private metrics = new Map<string, MetricState>();

  registerCounter(name: string, help: string): void {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, { type: 'counter', name, help, values: new Map() });
    }
  }

  registerGauge(name: string, help: string): void {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, { type: 'gauge', name, help, values: new Map() });
    }
  }

  registerHistogram(
    name: string,
    help: string,
    buckets: number[] = [0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10, 30, 60],
  ): void {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, {
        type: 'histogram',
        name,
        help,
        buckets: [...buckets].sort((a, b) => a - b),
        observations: new Map(),
      });
    }
  }

  incrementCounter(name: string, labels: MetricLabels = {}, value: number = 1): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'counter') return;
    const key = labelsToKey(labels);
    metric.values.set(key, (metric.values.get(key) ?? 0) + value);
  }

  setGauge(name: string, value: number, labels: MetricLabels = {}): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'gauge') return;
    const key = labelsToKey(labels);
    metric.values.set(key, value);
  }

  incrementGauge(name: string, labels: MetricLabels = {}, value: number = 1): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'gauge') return;
    const key = labelsToKey(labels);
    metric.values.set(key, (metric.values.get(key) ?? 0) + value);
  }

  observeHistogram(name: string, value: number, labels: MetricLabels = {}): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'histogram') return;
    const key = labelsToKey(labels);
    const obs = metric.observations.get(key) ?? [];
    obs.push(value);
    metric.observations.set(key, obs);
  }

  /**
   * Export all metrics in Prometheus text exposition format.
   */
  export(): string {
    const lines: string[] = [];

    for (const metric of this.metrics.values()) {
      lines.push(`# HELP ${metric.name} ${metric.help}`);
      lines.push(`# TYPE ${metric.name} ${metric.type}`);

      if (metric.type === 'counter' || metric.type === 'gauge') {
        for (const [key, value] of metric.values) {
          lines.push(`${metric.name}${formatLabels(key)} ${value}`);
        }
      } else if (metric.type === 'histogram') {
        for (const [key, observations] of metric.observations) {
          const sorted = [...observations].sort((a, b) => a - b);
          const sum = sorted.reduce((s, v) => s + v, 0);
          const count = sorted.length;
          const labelStr = key ? `,${key}` : '';

          for (const bucket of metric.buckets) {
            const le = sorted.filter((v) => v <= bucket).length;
            lines.push(`${metric.name}_bucket{le="${bucket}"${labelStr}} ${le}`);
          }
          lines.push(`${metric.name}_bucket{le="+Inf"${labelStr}} ${count}`);
          lines.push(`${metric.name}_sum${formatLabels(key)} ${sum}`);
          lines.push(`${metric.name}_count${formatLabels(key)} ${count}`);
        }
      }
    }

    return lines.join('\n') + '\n';
  }

  reset(): void {
    this.metrics.clear();
  }
}

// Singleton instance with pre-registered scan metrics
export const scanMetrics = new MetricsCollector();
scanMetrics.registerCounter('securityscan_scans_total', 'Total number of scans started');
scanMetrics.registerCounter('securityscan_scans_completed_total', 'Total number of scans completed');
scanMetrics.registerCounter('securityscan_scans_failed_total', 'Total number of scans failed');
scanMetrics.registerCounter('securityscan_findings_total', 'Total number of findings detected');
scanMetrics.registerGauge('securityscan_scans_active', 'Number of currently active scans');
scanMetrics.registerGauge('securityscan_payloads_active', 'Number of active payload definitions');
scanMetrics.registerHistogram(
  'securityscan_scan_duration_seconds',
  'Scan duration in seconds',
  [1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600],
);
scanMetrics.registerHistogram(
  'securityscan_http_request_duration_seconds',
  'HTTP request duration in seconds',
  [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
);
scanMetrics.registerHistogram(
  'securityscan_phase_duration_seconds',
  'Duration of individual scan pipeline phases in seconds',
  [0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600],
);
scanMetrics.registerHistogram(
  'securityscan_api_request_duration_seconds',
  'HTTP request latency in seconds for API endpoints',
  [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
);
scanMetrics.registerCounter(
  'securityscan_api_requests_total',
  'Total number of API HTTP requests handled',
);
scanMetrics.registerGauge(
  'securityscan_worker_jobs_active',
  'Number of active BullMQ scan jobs being processed',
);
