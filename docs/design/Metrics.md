# Metrics in Ratify
Author: Akash Singhal (@akashsinghal)

Apart from pod metrics, Ratify does not emit any application-specific metrics. This proposal aims to outline the design and implementation of an extensible metrics interface.

## Goals

- Add latency metrics for executor and verifiers
- Add request metrics for all registry, KMS (Key Management System), and identity network operations
- Add load metrics for number of External Data requests Ratify pod is processing
- Metrics implementation should be metrics provider agnostic
- Documentation on how to add new metrics provider
- Documentation for every metric implemented
- Dashboard (Nice to have)
- Instructions/helm chart updates for installing each metric provider

## Non Goals

-  Tracing support
-  Monitors

## Kubernetes metrics overview

Ratify will need to leverage a vendor-agnostic instrumentation library to report metrics and export them to a configured metrics ingester on the cluster. Many kubernetes projects, such as OPA Gatekeeper, rely on [OpenTelemetry](https://opentelemetry.io/). OpenTelemetry provides both metrics and tracing support leaving us the option to implement tracing in the future. (Note: OpenTelemetry is the result of the merger of two CNCF projects, OpenCensus and OpenTrace. OPA Gatekeeper's metrics implementation relies on OpenCensus and they will eventually need to upgrade to OpenTelemetry. This Ratify metrics design is loosely based on Gatekeeper's implementation)

With OpenTelemetry Ratify can easily support multiple metric consumer vendors. The most popular choice, and Ratify's first provider, is Prometheus.

### Open Telemetry workflow
OpenTelemetry exposes configurable providers throughout the metrics workflow:

- Instrument: The actual metric being emitted. OpenTelemetry support three types of instruments for collecting data (See more [here](https://opentelemetry.io/docs/concepts/signals/metrics))
    1. Counter: Value that accumulates over time. (e.g request count, signatures verified)
    2. Gauge: Point-in-time value of a continuous data stream (e.g speed, pressure)
    3. Histogram: Ratify-side aggregation of measurements. Bascially a complex aggregation of Counters where each bin is bounded from the min value (0) to the upper bin boundary. For example if we had bin boundaries [0, 1, 2, 3, 4, 5] and the measured value is 3.5, then the resulting histogram would be [0, 0, 0, 1, 1]. 
- Meter: Wraps a collection of instruments related to a specific scope. In Ratify's case, we'd have a single Meter with all of our instruments. The scope would be the Ratify application (`github.com/notaryproject/ratify`)
- Exporter: The vendor-specific metric reader implementation. Each exporter is responsible for consuming the metrics published to the data stream according to their vendor specification. The first provider we would support is Prometheus.
- View: Defines/overrides the behavior for how metrics should be collected (e.g changing the name of the instrument, changing the bin values of histogram instrument)
- Meter Provider: Creates the Meter and binds to the specified metric Exporter. It also is resonsible for mutating the metric data stream according to the Views specified in the options.

### Prometheus
Prometheus is a very popular metrics, monitoring, and database tool. It is time series based and is widely used in K8s. Prometheus metrics collection is pull-based. A prometheus instance is installed in the cluster. This instance is responsible for periodically "scraping" the metrics from the `/metrics` endpoint for each resource. Ratify's prometheus metrics provider implementation will be responsible for creating a new http server which will bind the `/metrics` endpoint to a prometheus handler. Once the OpenTelemetry Prometheus exporter is created, the handler will take care of publishing the correct Prometheus-formatted metrics. 


Scraping is achieved via annotations on the resources that expose metrics on the `/metrics` endpoint. There's two parts to this: First, how does prometheus know which resources to consider and what annotations to look for? The prometheus config is responsible for this. The configuration contains instructions on which annotations to look for to determine if a resource is eligible for scraping and which resources it should check. See an example config entry for a Pod spec [here](https://github.com/techiescamp/kubernetes-prometheus/blob/c318567cdb45597c29ebca600e5134a444a14e60/config-map.yaml#L78). For ratify, the metrics will be published by the Ratify pod. Second, how do we tell Prometheus to look for Ratify metrics specifically from the `/metrics` endpoint on the Ratify pod? We add annotations to the Ratify Deployment spec to indicate scraping and which port the metrics server is running on the pod.
```
annotations:
    prometheus.io/scrape: 'true'
    prometheus.io/port: '8888'
```

See example [here](https://github.com/techiescamp/kubernetes-prometheus/blob/c318567cdb45597c29ebca600e5134a444a14e60/prometheus-service.yaml#L6).

---

Ratify will initialize the Prometheus exporter server on startup and report metrics to the `/metrics` endpoint using OpenTelemetry. However, it is not responsible for installing prometheus on the actual cluster and providing the config. There's widely published prometheus charts for this purpose. We will provide an additional scraping config specifically for pod scraping. User can reference the sample scraping config to add to their prometheus deployment if they have not already enabled pod scraping.

## User Experience

Prometheus installation will be a recommended pre requesite. By default, Ratify will export metrics to the `/metrics` endpoint. However, it's up to the user if they choose to set up Prometheus on the cluster.

New Helm values:
- `metricsType`: string, default: "prometheus"
- `metricsPort`: int, default: 8888

Corresponding flags for exporter and port will be added to the ratify `serve` command to enable metrics emission in non K8s scenarios. 


## Proposed Metrics

Gatekeeper emits mutation and verification request metrics, however it seems they cannot be scoped to the external data and provider level.

Each histogram instrument by default wraps a counter which can then be used during dashboard creation to create other synthetic metrics such as rate of change. Furthermore, we can use the histogram to calculate a particular quantile of the histogram. The histogram metric inherently is an increasing aggregation of the past measurements, thus to understand the quantile value at a particular point of time, we must measure the rate of change of the histogram over a specified period of time. Once we have the rate of change, we can find the quantile according to the specified percentile. P95 is a standard choice. 

- Verification Request Duration
    - Instrument type: Histogram
    - Also contains Verification Request Count
    - Attributes:
        - subject count
- Mutation Request Duration
    - Instrument type: Histogram
    - Also contains Mutation Request Count
    - Attributes:
        - subject count
- Count of each request to the registry
    - Instrument type: Counter
    - Also contains registry request 
    - Attributes: registry, status code
    - Will be used for 429 count
- KeyVault Request Duration
    - Do we really care about this??
        - The Cert fetching operations happen independent of the external data request so timing isn't a concern
    - Instrument type: Histogram
    - Also contains keyvault request count
    - Attributes: keyvault name, certificate name
- Size of ORAS OCI cache folder
    - Do we really care about this?
        - The real concern here is OOM for the pod so then shouldn't we just use the pod memory metric here?
    - Instrument type: Gauge
    - checks the folder size of the ORAS OCI Store to see if pod will reach OOM
- Verifier Duration
    - Instrument type: Histogram
    - Attributes: verifier artifact type
- GetAADToken Duration (Azure Workload Identity)
    - Instrument type: Histogram
    - Attributes:
        - KeyVault vs ACR
- RefreshToken Duration (Azure Workload Identity)
    - Instrument type: Histogram
    - Attributes: registry name
- Verification Artifact Count per ED
    - Instrument type: Counter
    - Attributes:
- System Error count
    - Instrument type: Counter
    - Attributes: Maybe error type (Ratify doesn't have great error type standardization right now so this might not be very helpful initially)
    - Considerations:
        - Which errors should trigger this?

## Phase 1

- Implement open telemetry metrics reporter
- Define metrics exporter interfaces
- Add documentation for how to add new exporter implementation and where to specify exporter type
- Implement Prometheus metrics exporter
- Implement Prometheus metrics server
- Support small initial set of metrices:
    - Verification Request Duration
    - Mutation Request Duration
    - Verifier Duration
    - System Error count
- Add documentation for each metric

## Phase 2

- Switch ORAS store to use ORAS go's retryable http client instead of Hashicorps
- Add custom `RoundTripper` to ORAS http client to capture each request status code and duration
- Add accompanying metric for registry request duration

## Phase 3
- Implement remaining metrics


## Dashboard and Monitors
We should provide documentation on recommended prometheus monitors to add for specific metrics. We should also add links to dashboard tools that can integrate with the current set of metric exporters.

Sample Dashboard:
![](https://i.imgur.com/QNkvt9D.png)

### Grafana
Grafana is the most popular open source metrics dashboard. It works with many data sources including Prometheus. Ratify can build its own dashboard and publish it on Grafana's marketplace. This will make it easier for user's to discover the dashboard and quickly interact with Ratify metrics. We can also commit a sample Grafana dashboard code into Ratify for those looking to set up a dashboard in their own environment. 



