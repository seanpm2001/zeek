#include "zeek/telemetry/Histogram.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntHistogramFamily::IntHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels,
                                       std::string_view helptext, std::string_view unit,
                                       bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	}

IntHistogram IntHistogramFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	return IntHistogram{
		m->CreateUInt64Histogram(std::string{name}, std::string{helptext}, std::string{unit}),
		labels};
	}

IntHistogram::IntHistogram(opentelemetry::nostd::shared_ptr<Handle> hdl,
                           Span<const LabelView> labels) noexcept
	: hdl(std::move(hdl)), attributes(labels)
	{
	}

DblHistogramFamily::DblHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels,
                                       std::string_view helptext, std::string_view unit,
                                       bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	}

DblHistogram DblHistogramFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	return DblHistogram{
		m->CreateDoubleHistogram(std::string{name}, std::string{helptext}, std::string{unit}),
		labels};
	}

DblHistogram::DblHistogram(opentelemetry::nostd::shared_ptr<Handle> hdl,
                           Span<const LabelView> labels) noexcept
	: hdl(std::move(hdl)), attributes(labels)
	{
	}
