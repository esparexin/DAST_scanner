import { describe, it, expect, beforeEach } from 'vitest';
import { MetricsCollector, scanMetrics } from '../metrics-collector.js';

describe('MetricsCollector', () => {
  let collector: MetricsCollector;

  beforeEach(() => {
    collector = new MetricsCollector();
  });

  it('exports counter metrics in Prometheus format', () => {
    collector.registerCounter('http_requests_total', 'Total HTTP requests');
    collector.incrementCounter('http_requests_total', { method: 'GET' }, 5);
    collector.incrementCounter('http_requests_total', { method: 'POST' }, 3);

    const output = collector.export();
    expect(output).toContain('# HELP http_requests_total Total HTTP requests');
    expect(output).toContain('# TYPE http_requests_total counter');
    expect(output).toContain('http_requests_total{method="GET"} 5');
    expect(output).toContain('http_requests_total{method="POST"} 3');
  });

  it('exports gauge metrics', () => {
    collector.registerGauge('active_scans', 'Active scans');
    collector.setGauge('active_scans', 7);

    const output = collector.export();
    expect(output).toContain('# TYPE active_scans gauge');
    expect(output).toContain('active_scans 7');
  });

  it('exports histogram metrics with buckets', () => {
    collector.registerHistogram('request_duration', 'Request duration', [0.1, 0.5, 1.0]);
    collector.observeHistogram('request_duration', 0.05);
    collector.observeHistogram('request_duration', 0.3);
    collector.observeHistogram('request_duration', 0.8);
    collector.observeHistogram('request_duration', 1.5);

    const output = collector.export();
    expect(output).toContain('request_duration_bucket{le="0.1"} 1');
    expect(output).toContain('request_duration_bucket{le="0.5"} 2');
    expect(output).toContain('request_duration_bucket{le="1"} 3');
    expect(output).toContain('request_duration_bucket{le="+Inf"} 4');
    expect(output).toContain('request_duration_count 4');
  });

  it('increments gauge values', () => {
    collector.registerGauge('queue_depth', 'Queue depth');
    collector.incrementGauge('queue_depth', {}, 3);
    collector.incrementGauge('queue_depth', {}, 2);

    const output = collector.export();
    expect(output).toContain('queue_depth 5');
  });

  it('scanMetrics singleton has pre-registered scan metrics', () => {
    const output = scanMetrics.export();
    expect(output).toContain('securityscan_scans_total');
    expect(output).toContain('securityscan_findings_total');
    expect(output).toContain('securityscan_scans_active');
    expect(output).toContain('securityscan_scan_duration_seconds');
    expect(output).toContain('securityscan_http_request_duration_seconds');
    expect(output).toContain('securityscan_payloads_active');
  });
});
