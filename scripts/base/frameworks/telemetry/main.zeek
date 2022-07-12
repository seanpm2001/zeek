## Module providing helpers to collect telemetry. This is wraps
## the somewhat lower-level telemetry.bif functions.
module Telemetry;

export {
	type labels_table: table[string] of string;
	type labels_vector: vector of string;

	## Default bounds/buckets for histograms if no bounds are explicitly provided.
	const default_histogram_bounds = vector(0.01, 0.1, 1.0, 10.0, 30.0, 60.0) &redef;

	## Options type shared by all metric types
	type MetricOpts: record {
		prefix: string;
		name: string;
		## Use the pseudo-unit "1" if this is a unit-less metric.
		unit: string;
		## Documentation for this metric.
		helptext: string &default="Zeek Script Metric";
		labels: vector of string &default=vector();
		is_total: bool &optional;

		## Only used when creating HistogramFamily instances.
		bounds: vector of double &default=default_histogram_bounds;
	};

	type CounterFamily: record {
		__family: opaque of dbl_counter_metric_family;
		__labels: vector of string;
	};

	type Counter: record {
		__metric: opaque of dbl_counter_metric;
	};

	## Register a counter family. The return value is a
	## :zeek:see:`Telemetry:CounterFamily`
	## instance that can be used with :zeek:see`Telemetry::counter_with`
	## and :zeek:see:`Telemetry::counter_with_v()`
	global register_counter_family: function(opts: MetricOpts): CounterFamily;

	## Get a handle to a Counter of the given family and label values.
	global counter_with: function(cf: CounterFamily,
	                              label_values: labels_vector &default=vector()): Counter;

	## Get a Counter instance from a CounterFamily by providing
	## label values as a table.
	global counter_with_t: function(cf: CounterFamily,
	                                labels: labels_table &default=table()): Counter;

	## Increment a Counter through the CounterFamily
	## Using a negative amount is an error.
	global counter_inc: function(c: Counter, amount: double &default=1.0): bool;

	## Helper to set a counter to given value.
	## Setting a value that is less than the current value is an error
	## and will be ignored. Use this only to track increasing values.
	global counter_set: function(c: Counter, value: double): bool;

	## Increment a Counter through the CounterFamily
	## Using a negative amount is an error.
	global counter_family_inc: function(c: CounterFamily,
	                                    label_values: labels_vector &default=vector(),
	                                    amount: double &default=1.0): bool;

	## Increment a Counter through the CounterFamily
	## Using a negative amount is an error.
	global counter_family_inc_t: function(c: CounterFamily,
	                                      labels: labels_table &default=table(),
	                                      amount: double &default=1.0): bool;

	## Helper to set a Counter through the CounterFamily.
	global counter_family_set: function(c: CounterFamily,
	                                    value: double,
	                                    label_values: labels_vector &default=vector()): bool;

	## Helper to set a Counter through the CounterFamily.
	global counter_family_set_t: function(c: CounterFamily,
	                                      value: double,
	                                      labels: labels_table &default=table()): bool;

	type GaugeFamily: record {
		__family: opaque of dbl_gauge_metric_family;
		__labels: vector of string;
	};

	type Gauge: record {
		__metric: opaque of dbl_gauge_metric;
	};

	global register_gauge_family: function(opts: MetricOpts): GaugeFamily;


	## Convenience function to use a vector of label values rather
	## than the table as :zeek:see:`GaugeFamily:gauge_with` expects.
	global gauge_with: function(gf: GaugeFamily,
	                            label_values: labels_vector &default=vector()): Gauge;

	## Get a Gauge instance from a GaugeFamily by providing
	## label values as a table.
	global gauge_with_t: function(gf: GaugeFamily,
	                              labels: labels_table &default=table()): Gauge;

	## Increment a gauge by the given amount.
	global gauge_inc: function(g: Gauge, amount: double &default=1.0): bool;
	## Decrement a gauge by the given amount.
	global gauge_dec: function(g: Gauge, amount: double &default=1.0): bool;
	## Set a gauge to the given value.
	global gauge_set: function(g: Gauge, value: double): bool;

	## Increment a Gauge by the given amount through a GaugeFamily.
	global gauge_family_inc: function(g: GaugeFamily,
	                                  label_values: labels_vector &default=vector(),
	                                  amount: double &default=1.0): bool;
	## Decrement a Gauge by the given amount through a GaugeFamily.
	global gauge_family_dec: function(g: GaugeFamily,
	                                  label_values: labels_vector &default=vector(),
	                                  amount: double &default=1.0): bool;
	## Set a Gauge by the given amount through a GaugeFamily.
	global gauge_family_set: function(g: GaugeFamily,
	                                  value: double,
	                                  label_values: labels_vector &default=vector()): bool;

	## Increment a Gauge by the given amount through a GaugeFamily.
	global gauge_family_inc_t: function(g: GaugeFamily,
	                                    labels: labels_table &default=table(),
	                                    amount: double &default=1.0): bool;

	## Decrement a Gauge by the given amount through a GaugeFamily.
	global gauge_family_dec_t: function(g: GaugeFamily,
	                                    labels: labels_table &default=table(),
	                                    amount: double &default=1.0): bool;

	## Set a Gauge by the given amount through a GaugeFamily.
	global gauge_family_set_t: function(g: GaugeFamily,
	                                    value: double,
	                                    labels: labels_table &default=table()): bool;
	type HistogramFamily: record {
		__family: opaque of dbl_histogram_metric_family;
		__labels: vector of string;
	};

	type Histogram: record {
		__metric: opaque of dbl_histogram_metric;
	};

	global register_histogram_family: function(opts: MetricOpts): HistogramFamily;
	global histogram_with: function(hf: HistogramFamily,
	                                label_values: labels_vector &default=vector()): Histogram;

	global histogram_with_t: function(hf: HistogramFamily,
	                                  labels: labels_table &default=table()): Histogram;

	## Observe a measurement for a Histogram
	global histogram_observe: function(h: Histogram, measurement: double): bool;

	## Observe a measurement through a HistogramFamily
	global histogram_family_observe: function(hf: HistogramFamily,
	                                          measurement: double,
	                                          label_values: labels_vector &default=vector()): bool;

	global histogram_family_observe_t: function(hf: HistogramFamily,
	                                            measurement: double,
	                                            labels: labels_table &default=table()): bool;

	## Collection hook. This hook is invoked collect_interval and allows
	## users to update their metrics on a regular basis.
	##
	## Implementations should be light-weight, collect() may be called
	## at high-frequencies. Not multiple times per second, but likely
	## multiple times per minute.
	##
	## TBD: Have a second hook running at a much lower frequency for
	##      metrics that are heavy to collect?
	global collect: hook();

	## Could also see a collect() hook in the future that has an output
	## parameter so implementors would yield metrics rather than setting
	## values on instances.

	## Interval in which the collect hook is invoked.
	option collect_interval = 10sec;

	# API for listing/iterating metrics follows.

	## For introspection.
	type MetricType: enum {
		DBL_COUNTER,
		INT_COUNTER,
		DBL_GAUGE,
		INT_GAUGE,
		DBL_HISTOGRAM,
		INT_HISTOGRAM,
	};

	## Entry returned by :zeek:see:`Telemetry::list_metrics()`
	type Metric: record {
		opts: MetricOpts;

		## The labels associated with this Metric.
		label_values: vector of string;

		## The value of gauge or counter types cast to a double
		## independent of the underlying type.
		value: double &optional;

		## The count value of the underlying gauge or counter
		## if the int version is in use.
		count_value: count &optional;

		## Internal metric type.
		metric_type: MetricType;
	};

	## List all existing Metric instances matching the given
	## name and prefix. For gauge and counter metrics their
	## current value is included in the result.
	## `prefix` and `name` support globbing.
	## By default, all metrics with the "zeek" prefix are returned.
	global list_metrics: function(name: string &default="*",
	                              prefix: string &default="zeek"): vector of Metric;

	## Separate API to list histograms as expanded counters.
	global list_histograms_expanded: function(name: string &default="*",
	                                          prefix: string &default="zeek"): vector of Metric;
}


## Internal helper to create the labels table.
function make_labels(keys: vector of string, values: labels_vector): labels_table
	{
	local labels: labels_table;
	for ( i in keys )
		labels[keys[i]] = values[i];
	return labels;
	}

function register_counter_family(opts: MetricOpts): CounterFamily
	{
	local f = Telemetry::__dbl_counter_family(
		opts$prefix,
		opts$name,
		opts$labels,
		opts$helptext,
		opts$unit,
		opts?$is_total ? opts$is_total : T
	);
	return CounterFamily($__family=f, $__labels=opts$labels);
	}

# Fallback Counter returned when there are issues with the labels.
global error_counter_cf = register_counter_family([
	$prefix="zeek",
	$name="telemetry_counter_usage_error",
	$unit="1",
	$helptext="This counter is returned when label usage for counters is wrong. Check reporter.log if non-zero."
]);

function counter_with(cf: CounterFamily, label_values: labels_vector): Counter
	{
	if ( |cf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |cf$__labels|, |label_values|));
		return counter_with(error_counter_cf);
		}
	return counter_with_t(cf, make_labels(cf$__labels, label_values));
	}

function counter_with_t(cf: CounterFamily, labels: labels_table): Counter
	{

	# We could pre-check in script land that labels agree, but the
	# Telemetry subsystem will do it, too.
	local m = Telemetry::__dbl_counter_metric_get_or_add(cf$__family, labels);
	return Counter($__metric=m);
	}

function counter_inc(c: Counter, amount: double): bool
	{
	return Telemetry::__dbl_counter_inc(c$__metric, amount);
	}

function counter_set(c: Counter, value: double): bool
	{
	local cur_value: double = Telemetry::__dbl_counter_value(c$__metric);
	if (value < cur_value)
		{
		Reporter::error(fmt("Attempted to set lower counter value=%s cur_value=%s", value, cur_value));
		return F;
		}
	return Telemetry::__dbl_counter_inc(c$__metric, value - cur_value);
	}

function counter_family_inc(cf: CounterFamily, label_values: labels_vector, amount: double): bool
	{
	return counter_inc(counter_with(cf, label_values), amount);
	}

function counter_family_inc_t(cf: CounterFamily, labels: labels_table, amount: double): bool
	{
	return counter_inc(counter_with_t(cf, labels), amount);
	}

function counter_family_set(cf: CounterFamily, value: double, label_values: labels_vector): bool
	{
	return counter_set(counter_with(cf, label_values), value);
	}

function counter_family_set_t(cf: CounterFamily, value: double, labels: labels_table): bool
	{
	return counter_set(counter_with_t(cf, labels), value);
	}

function register_gauge_family(opts: MetricOpts): GaugeFamily
	{
	local f = Telemetry::__dbl_gauge_family(
		opts$prefix,
		opts$name,
		opts$labels,
		opts$helptext,
		opts$unit,
		opts?$is_total ? opts$is_total : F
	);
	return GaugeFamily($__family=f, $__labels=opts$labels);
	}

# Fallback Gauge returned when there are issues with the label usage.
global error_gauge_cf = register_gauge_family([
	$prefix="zeek",
	$name="telemetry_gauge_usage_error",
	$unit="1",
	$helptext="This gauge is returned when label usage for gauges is wrong. Check reporter.log if non-zero."
]);

function gauge_with(gf: GaugeFamily, label_values: labels_vector): Gauge
	{
	if ( |gf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |gf$__labels|, |label_values|));
		return gauge_with(error_gauge_cf);
		}

	return gauge_with_t(gf, make_labels(gf$__labels, label_values));
	}

function gauge_with_t(gf: GaugeFamily, labels: labels_table): Gauge
	{
	local m = Telemetry::__dbl_gauge_metric_get_or_add(gf$__family, labels);
	return Gauge($__metric=m);
	}

function gauge_inc(g: Gauge, amount: double &default=1.0): bool
	{
	return Telemetry::__dbl_gauge_inc(g$__metric, amount);
	}

function gauge_dec(g: Gauge, amount: double &default=1.0): bool
	{
	return Telemetry::__dbl_gauge_dec(g$__metric, amount);
	}

function gauge_set(g: Gauge, value: double): bool
	{
	# Telemetry currently does not implement __dbl_gauge_set(), do
	# it by hand here.
	local cur_value: double = Telemetry::__dbl_gauge_value(g$__metric);
	if (value > cur_value)
		return Telemetry::__dbl_gauge_inc(g$__metric, value - cur_value);

	return Telemetry::__dbl_gauge_dec(g$__metric, cur_value - value);
	}

function gauge_family_inc(g: GaugeFamily, label_values: labels_vector, value: double): bool
	{
	return gauge_inc(gauge_with(g, label_values), value);
	}

function gauge_family_dec(g: GaugeFamily, label_values: labels_vector, value: double): bool
	{
	return gauge_dec(gauge_with(g, label_values), value);
	}

function gauge_family_set(g: GaugeFamily, value: double, label_values: labels_vector): bool
	{
	return gauge_set(gauge_with(g, label_values), value);
	}

function gauge_family_inc_t(g: GaugeFamily, labels: labels_table, value: double): bool
	{
	return gauge_inc(gauge_with_t(g, labels), value);
	}

function gauge_family_dec_t(g: GaugeFamily, labels: labels_table, value: double): bool
	{
	return gauge_dec(gauge_with_t(g, labels), value);
	}

function gauge_family_set_t(g: GaugeFamily, value: double, labels: labels_table): bool
	{
	return gauge_set(gauge_with_t(g, labels), value);
	}

function register_histogram_family(opts: MetricOpts): HistogramFamily
	{
		local f = Telemetry::__dbl_histogram_family(
			opts$prefix,
			opts$name,
			opts$labels,
			opts$bounds,
			opts$helptext,
			opts$unit,
			opts?$is_total ? opts$is_total : F
		);
		return HistogramFamily($__family=f, $__labels=opts$labels);
	}

# Fallback Histogram when there are issues with the labels.
global error_histogram_hf = register_histogram_family([
	$prefix="zeek",
	$name="telemetry_histogram_usage_error",
	$unit="1",
	$helptext="This histogram is returned when label usage for histograms is wrong. Check reporter.log if non-zero.",
	$bounds=vector(1.0)
]);
#
function histogram_with(hf: HistogramFamily, label_values: labels_vector): Histogram
	{
	if ( |hf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |hf$__labels|, |label_values|));
		return histogram_with(error_histogram_hf);
		}

	return histogram_with_t(hf, make_labels(hf$__labels, label_values));
	}

function histogram_with_t(hf: HistogramFamily, labels: labels_table &default=table()): Histogram
	{
	local m = Telemetry::__dbl_histogram_metric_get_or_add(hf$__family, labels);
	return Histogram($__metric=m);
	}

function histogram_observe(h: Histogram, measurement: double): bool
	{
	return Telemetry::__dbl_histogram_observe(h$__metric, measurement);
	}

function histogram_family_observe(hf: HistogramFamily, measurement: double, label_values: labels_vector): bool
	{
	return histogram_observe(histogram_with(hf, label_values), measurement);
	}

function histogram_family_observe_t(hf: HistogramFamily, measurement: double, label_values: labels_table): bool
	{
	return histogram_observe(histogram_with_t(hf, label_values), measurement);
	}

event run_collect_hook()
	{
	hook Telemetry::collect();
	schedule collect_interval { run_collect_hook() };
	}

event zeek_init()
	{
	schedule collect_interval { run_collect_hook() };
	}


module TelemetryExamples;

## Example: Tracking connections by protocol and service through connection_state_remove.
#
#    $ curl -s localhost:4242/metrics | grep ^zeek_connection_services_total
#    zeek_connection_services_total{endpoint="",protocol="tcp",service="unknown"} 23.000000 1656605772830
#    zeek_connection_services_total{endpoint="",protocol="udp",service="dns"} 586.000000 1656605772830
#    zeek_connection_services_total{endpoint="",protocol="tcp",service="ssl"} 22.000000 1656605772830
#    zeek_connection_services_total{endpoint="",protocol="icmp",service="unknown"} 8.000000 1656605772830
#    zeek_connection_services_total{endpoint="",protocol="udp",service="unknown"} 27.000000 1656605772830
#    zeek_connection_services_total{endpoint="",protocol="tcp",service="http"} 1.000000 1656605772830
#    zeek_connection_services_total{endpoint="",protocol="udp",service="ntp"} 3.000000 1656605772830
#

# Globally construct the CounterFamily type. Concrete instances are created
# via Telemetry::counter_with() or Telemetry::counter_with_t()
global conn_by_service_cf = Telemetry::register_counter_family([
	$prefix="zeek",
	$name="connection_services",
	$unit="1",
	$labels=vector("protocol", "service")
]);

# Also track connection durations in a Histogram using the default bounds/buckets.
global conn_durations_hf = Telemetry::register_histogram_family([
	$prefix="zeek",
	$name="connection_durations",
	$unit="1",
	$labels=vector("proto", "service")
]);

# We could add a custom caching table with key "<proto>-<service>" if
# the on-demand creation of Counter objects would be too expensive.
event connection_state_remove(c: connection)
	{
	local proto = cat(c$conn$proto);
	if ( |c$service| == 0 )
		{
		print(fmt("Unknown %s", c$id));
		local c1 = Telemetry::counter_with(conn_by_service_cf,
		                                   vector(proto, "unknown"));
		Telemetry::counter_inc(c1);

		local h1 = Telemetry::histogram_with(conn_durations_hf, vector(proto, "unknown"));
		Telemetry::histogram_observe(h1, interval_to_double(c$duration));
		}

	for (s in c$service)
		{
		print(fmt("%s %s", s, c$id));
		local c2 = Telemetry::counter_with(conn_by_service_cf,
		                                   vector(proto, to_lower(s)));
		Telemetry::counter_inc(c2);

		local h2 = Telemetry::histogram_with(conn_durations_hf, vector(proto, to_lower(s)));
		Telemetry::histogram_observe(h2, interval_to_double(c$duration));
		}
	}


# Example: Tracking intel matches by indicator_type within Intel::match()
#
# Shows usage of labels as table, labels as vector and caching of Counter
# instances by the user as well.
#
# NOTE: This increments the counter multiple times per match for
#       demonstration purposes only.
#
#     $ curl -sf http://localhost:4243/metrics | grep intel_matches
#     # HELP zeek_intel_matches_total Zeek Script Metric
#     # TYPE zeek_intel_matches_total counter
#     zeek_intel_matches_total{endpoint="",indicator_type="intel::domain"} 25.000000 1656951295319
#     zeek_intel_matches_total{endpoint="",indicator_type="intel::url"} 5.000000 1656951295319
#     zeek_intel_matches_total{endpoint="",indicator_type="intel::addr"} 5.000000 1656951295319

@load base/frameworks/intel
@load policy/frameworks/intel/seen

global intel_matches_cf = Telemetry::register_counter_family([
	$prefix="zeek",
	$name="intel_matches",
	$unit="1",
	$labels=vector("indicator_type")
]);

# Caching counter instances
global intel_matches_counter_cache: table[string] of Telemetry::Counter;

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	print(fmt("Intel::match: %s %s items=%s", s$indicator, s$indicator_type, |items|));
	local indicator_type = to_lower(cat(s$indicator_type));
	Telemetry::counter_family_inc(intel_matches_cf, vector(indicator_type));

	# More verbose: table of labels.
	Telemetry::counter_family_inc_t(intel_matches_cf, table(["indicator_type"] = indicator_type));

	# User-side cached version of counters.
	#
	# We could do transparent caching in the Telemetry module,
	# but maybe for now leave it out and put the burden on the
	# user for high-frequency events (if that's actually needed).
	if ( indicator_type !in intel_matches_counter_cache )
		intel_matches_counter_cache[indicator_type] = Telemetry::counter_with(intel_matches_cf, vector(indicator_type));
	local c = intel_matches_counter_cache[indicator_type];
	Telemetry::counter_inc(c);
	}

# Example: Expose how many indicator types have been loaded. This
# is using Telemetry::gauge_family_set() shortcut.
#
#    $ curl -sf http://localhost:4243/metrics | grep intel_indicators
#    # HELP zeek_intel_indicators Zeek Script Metric
#    # TYPE zeek_intel_indicators gauge
#    zeek_intel_indicators{endpoint="",indicator_type="addr"} 1.000000 1656951371148
#    zeek_intel_indicators{endpoint="",indicator_type="subnet"} 2.000000 1656951371148
#    zeek_intel_indicators{endpoint="",indicator_type="domain"} 3.000000 1656951371148
#    zeek_intel_indicators{endpoint="",indicator_type="user_name"} 3.000000 1656951371148
#    zeek_intel_indicators{endpoint="",indicator_type="url"} 2.000000 1656951371148
#
# An alternative implementation could extend the intel framework to expose
# these numbers as stats without needing to poke at the implementation
# details and iterating the whole table over and over again.

module Intel;

global intel_gauge_gf  = Telemetry::register_gauge_family([
	$prefix="zeek",
	$name="intel_indicators",
	$unit="1",
	$labels=vector("indicator_type"),
	$helptext="Number of Intel indicators loaded"
]);

hook Telemetry::collect()
	{
	print("Telemetry::collect() - intel");
	local g: Telemetry::Gauge;

	Telemetry::gauge_family_set(intel_gauge_gf,
	                            |Intel::min_data_store$host_data|,
	                            vector("addr"));

	Telemetry::gauge_family_set(intel_gauge_gf,
	                            |Intel::min_data_store$subnet_data|,
	                            vector("subnet"));

	# Group the string_data set by type and count entries.
	local counts: table[string] of count &default=0;
	for ([k, _type] in Intel::min_data_store$string_data)
		{
		# Intel::USER_NAME -> user_name
		local key = to_lower(split_string(cat(_type), /::/)[1]);
		counts[key] += 1;
		}

	for ([k], v in counts)
		Telemetry::gauge_family_set(intel_gauge_gf, v, vector(k));
	}

global log_writes_cf = Telemetry::register_counter_family([
	$prefix="zeek",
	$name="log_writes",
	$unit="1",
	$labels=vector("name")
]);

# Example: Track number of log writes per log stream via counters.
#
hook Log::log_stream_policy(rec: any, id: Log::ID)
	{
	Telemetry::counter_family_inc(log_writes_cf, vector(cat(id)));
	}

# Example: Expose pending timers and current connections through
#          scriptland gauges, update them within the Telemetry::collect hook.
#
#    curl -sf http://localhost:4242/metrics | grep -e timers -e connections
#    # HELP zeek_timers_total Total number of timers created.
#    # TYPE zeek_timers_total counter
#    zeek_timers_total{endpoint=""} 196.000000 1657010240858
#    # HELP zeek_active_timers Currently active timers.
#    # TYPE zeek_active_timers gauge
#    zeek_active_timers{endpoint=""} 66.000000 1657010240858
#    # HELP zeek_current_connections Currently active connections.
#    # TYPE zeek_current_connections gauge
#    zeek_current_connections{endpoint=""} 19.000000 1657010240858
#
# These things may be better tracked in core C++ code rather than on
# a script-level.
#
global current_conns_gf = Telemetry::register_gauge_family([
	$prefix="zeek",
	$name="current_connections",
	$unit="1",
	$helptext="Currently active connections."
]);
global current_conns_g = Telemetry::gauge_with(current_conns_gf);

global current_timers_gf = Telemetry::register_gauge_family([
	$prefix="zeek",
	$name="active_timers",
	$unit="1",
	$helptext="Currently active timers."
]);
global current_timers_g = Telemetry::gauge_with(current_timers_gf);

# This ends-up being zeek_timers_total on the Prometheus side.
global total_timers_cf = Telemetry::register_counter_family([
	$prefix="zeek",
	$name="timers",
	$unit="1",
	$helptext="Total number of timers created."
]);
global total_timers_c = Telemetry::counter_with(total_timers_cf);

hook Telemetry::collect()
	{
	print("Telemetry::collect() - conn and timer stats");
	local cs = get_conn_stats();
	Telemetry::gauge_set(current_conns_g, cs$current_conns);
	local ts = get_timer_stats();
	Telemetry::gauge_set(current_timers_g, ts$current);
	Telemetry::counter_set(total_timers_c, ts$cumulative);
	}


# Example: Counting x509 extensions in a table and sync'ing to the merics
#          during the Telemetry::collect() hook.
global x509_extensions_cf = Telemetry::register_counter_family([
	$prefix="zeek",
	$name="x509_extensions",
	$unit="1",
	$labels=vector("name")
]);

global x509_extension_counts: table[string] of count &default=0;

event x509_extension(f: fa_file, ext: X509::Extension)
	{
	++x509_extension_counts[ext$name];
	}

hook Telemetry::collect()
	{
	for ( k ,v in x509_extension_counts )
		Telemetry::counter_family_set(Intel::x509_extensions_cf, v, vector(k));
	}
