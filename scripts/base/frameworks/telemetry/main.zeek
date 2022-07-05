module Telemetry;

export {
	type labels_table: table[string] of string;
	type labels_vector: vector of string;

	type CounterOpts: record {
		prefix: string;
		name: string;
		## Use the pseudo-unit "1" if this is a unit-less metric.
		unit: string;
		## Documentation for this metric.
		helptext: string &default="Zeek Script Metric";
		labels: vector of string &default=vector();
		is_total: bool &default=T;
	};

	type CounterFamily: record {
		__family: opaque of dbl_counter_metric_family;
		__labels: vector of string;
	};

	type Counter: record {
		__metric: opaque of dbl_counter_metric;
	};

	## Register a counter. The return value is a :zeek:see:`Telemetry:CounterFamily`
	## instance that can be used with :zeek:see`Telemetry::counter_with`
	## and :zeek:see:`Telemetry::counter_with_v()`
	global register_counter: function(opts: CounterOpts): CounterFamily;

	## Get a Counter instance from a CounterFamily by providing
	## label values as a table.
	global counter_with: function(cf: CounterFamily, labels: labels_table &default=table()): Counter;
	## Get a handle to a Counter of the given family and label values.
	global counter_with_v: function(cf: CounterFamily, label_values: labels_vector &default=vector()): Counter;

	## Increment Counter by amount.
	## Using a negative amount is an error.
	global counter_inc: function(c: Counter, amount: double &default=1.0): bool;

	## Helper to set a counter to given value.
	## Setting a value that is less than the current value is an error
	## and will be ignored. Use this only to track increasing values.
	global counter_set: function(c: Counter, value: double): bool;

	## Shortcut for incrementing a Counter instances without exposure
	## to the intermediary objects using CounterOpts only.
	global counter_opts_inc: function(opts: CounterOpts, labels: labels_table &default=table(), amount: double &default=1.0): bool;

	## Shortcut for incrementing a Counter instance without exposure
	## to the intermediary objects using CounterOpts only.
	global counter_opts_inc_v: function(opts: CounterOpts, label_values: labels_vector &default=vector(), amount: double &default=1.0): bool;

	global counter_opts_set: function(opts: CounterOpts, value: double, labels: labels_table &default=table()): bool;
	global counter_opts_set_v: function(opts: CounterOpts, value: double, label_values: labels_vector &default=vector()): bool;

	type GaugeOpts: record {
		prefix: string;
		name: string;
		## Use the pseudo-unit "1" if this is a unit-less metric.
		unit: string;
		## Documentation for this metric.
		helptext: string &default="Zeek Script Metric";
		labels: vector of string &default=vector();
		is_total: bool &default=F;
	};

	type GaugeFamily: record {
		__family: opaque of dbl_gauge_metric_family;
		__labels: vector of string;
	};

	type Gauge: record {
		__metric: opaque of dbl_gauge_metric;
	};

	global register_gauge: function(opts: GaugeOpts): GaugeFamily;

	## Get a Gauge instance from a GaugeFamily by providing
	## label values as a table.
	global gauge_with: function(gf: GaugeFamily, labels: labels_table &default=table()): Gauge;

	## Convenience function to use a vector of label values rather
	## than the table as :zeek:see:`GaugeFamily:gauge_with` expects.
	global gauge_with_v: function(gf: GaugeFamily, label_values: labels_vector &default=vector()): Gauge;

	## Increment a gauge by the given amount.
	global gauge_inc: function(g: Gauge, amount: double &default=1.0): bool;
	## Decrement a gauge by the given amount.
	global gauge_dec: function(g: Gauge, amount: double &default=1.0): bool;
	## Set a gauge to the given value.
	global gauge_set: function(g: Gauge, value: double): bool;

	# Shortcuts using options only
	global gauge_opts_inc: function(opts: GaugeOpts, labels: labels_table &default=table(), amount: double &default=1.0): bool;
	global gauge_opts_dec: function(opts: GaugeOpts, labels: labels_table &default=table(), amount: double &default=1.0): bool;
	global gauge_opts_set: function(opts: GaugeOpts, value: double, labels: labels_table &default=table()): bool;

	global gauge_opts_inc_v: function(opts: GaugeOpts, label_values: labels_vector &default=vector(), amount: double &default=1.0): bool;
	global gauge_opts_dec_v: function(opts: GaugeOpts, label_values: labels_vector &default=vector(), amount: double &default=1.0): bool;
	global gauge_opts_set_v: function(opts: GaugeOpts, value: double, label_values: labels_vector &default=vector()): bool;

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
}


## Internal helper to create the labels table.
function make_labels(keys: vector of string, values: labels_vector): labels_table
	{
	local labels: labels_table;
	for ( i in keys )
		labels[keys[i]] = values[i];
	return labels;
	}

function register_counter(opts: CounterOpts): CounterFamily
	{
	local f = Telemetry::__dbl_counter_family(
		opts$prefix,
		opts$name,
		opts$labels,
		opts$helptext,
		opts$unit,
		opts$is_total  # is_sum
	);
	return CounterFamily($__family=f, $__labels=opts$labels);
	}

# Fallback Counter returned when there are issues with the labels.
global error_counter_cf = register_counter([
	$prefix="zeek",
	$name="telemetry_counter_usage_error",
	$unit="1",
	$helptext="This counter is returned when label usage of counters is wrong. Check reporter.log if non-zero."
]);

function counter_with(cf: CounterFamily, labels: labels_table): Counter
	{

	# We could pre-check in script land that labels agree, but the
	# Telemetry subsystem will do it, too.
	local m = Telemetry::__dbl_counter_metric_get_or_add(cf$__family, labels);

	return Counter($__metric=m);
	}

function counter_with_v(cf: CounterFamily, label_values: labels_vector): Counter
	{
	if ( |cf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |cf$__labels|, |label_values|));
		return counter_with(error_counter_cf);
		}

	return counter_with(cf, make_labels(cf$__labels, label_values));
	}

function counter_inc(c: Counter, amount: double &default=1.0): bool
	{
	return Telemetry::__dbl_counter_inc(c$__metric, amount);
	}

function counter_set(c: Counter, value: double &default=1.0): bool
	{
	local cur_value: double = Telemetry::__dbl_counter_value(c$__metric);
	if (value < cur_value)
		{
		Reporter::error(fmt("Attempted to set lower counter value=%s cur_value=%s", value, cur_value));
		return F;
		}

	return Telemetry::__dbl_counter_inc(c$__metric, value - cur_value);
	}

### Implementations for counter wrappers / short-cuts.

function counter_opts_inc(opts: CounterOpts, labels: labels_table, amount: double &default=1.0): bool
	{
	return counter_inc(counter_with(register_counter(opts), labels), amount);
	}

function counter_opts_inc_v(opts: CounterOpts, label_values: labels_vector, amount: double &default=1.0): bool
	{
	return counter_inc(counter_with_v(register_counter(opts), label_values), amount);
	}

function counter_opts_set(opts: CounterOpts, value: double, labels: labels_table &default=table()): bool
	{
	return counter_set(counter_with(register_counter(opts), labels), value);
	}
function counter_opts_set_v(opts: CounterOpts, value: double, label_values: labels_vector &default=vector()): bool
	{
	return counter_set(counter_with_v(register_counter(opts), label_values), value);
	}

function register_gauge(opts: GaugeOpts): GaugeFamily
	{
	local f = Telemetry::__dbl_gauge_family(
		opts$prefix,
		opts$name,
		opts$labels,
		opts$helptext,
		opts$unit,
		opts$is_total  # is_sum
	);

	return GaugeFamily($__family=f, $__labels=opts$labels);
	}

# Fallback Gauge returned when there are issues with the label usage.
global error_gauge_cf = register_gauge([
	$prefix="zeek",
	$name="telemetry_gauge_usage_error",
	$unit="1",
	$helptext="This gauge is returned when label usage for gauges is wrong. Check reporter.log if non-zero."
]);

function gauge_with(gf: GaugeFamily, labels: labels_table): Gauge
	{
	local m = Telemetry::__dbl_gauge_metric_get_or_add(gf$__family, labels);
	return Gauge($__metric=m);
	}

function gauge_with_v(gf: GaugeFamily, label_values: labels_vector): Gauge
	{
	if ( |gf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |gf$__labels|, |label_values|));
		return gauge_with(error_gauge_cf);
		}

	return gauge_with(gf, make_labels(gf$__labels, label_values));
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

### Implementations for gauge wrappers / short-cuts.

function gauge_opts_inc(opts: GaugeOpts, labels: labels_table &default=table(), amount: double &default=1.0): bool
	{
	return gauge_inc(gauge_with(register_gauge(opts), labels), amount);
	}

function gauge_opts_dec(opts: GaugeOpts, labels: labels_table &default=table(), amount: double &default=1.0): bool
	{
	return gauge_dec(gauge_with(register_gauge(opts), labels), amount);
	}

function gauge_opts_set(opts: GaugeOpts, value: double, labels: labels_table &default=table()): bool
	{
	return gauge_set(gauge_with(register_gauge(opts), labels), value);
	}

function gauge_opts_inc_v(opts: GaugeOpts, label_values: labels_vector &default=vector(), amount: double &default=1.0): bool
	{
	return gauge_inc(gauge_with_v(register_gauge(opts), label_values), amount);
	}
function gauge_opts_dec_v(opts: GaugeOpts, label_values: labels_vector &default=vector(), amount: double &default=1.0): bool
	{
	return gauge_dec(gauge_with_v(register_gauge(opts), label_values), amount);
	}

function gauge_opts_set_v(opts: GaugeOpts, value: double, label_values: labels_vector &default=vector()): bool
	{
	return gauge_set(gauge_with_v(register_gauge(opts), label_values), value);
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
# via Telemetry::counter_with_v().
global conn_by_service_cf = Telemetry::register_counter([
	$prefix="zeek",
	$name="connection_services",
	$unit="1",
	$labels=vector("protocol", "service")
]);

# The creation of the Counter objects here may be performance critical.
# We could add a custom caching table with key "<proto>-<service>" or
# indexed by a label vector as table[vector of string] of Counter.
event connection_state_remove(c: connection)
	{
	local proto = cat(c$conn$proto);
	if ( |c$service| == 0 )
		{
		print(fmt("Unknown %s", c$id));
		local c1 = Telemetry::counter_with_v(conn_by_service_cf,
		                                     vector(proto, "unknown"));
		Telemetry::counter_inc(c1);
		}

	for (s in c$service)
		{
		print(fmt("%s %s", s, c$id));
		local c2 = Telemetry::counter_with_v(conn_by_service_cf,
		                                     vector(proto, to_lower(s)));
		Telemetry::counter_inc(c2);
		}
	}


# Example: Tracking intel matches by indicator_type of Seen within Intel::match()
#
# Shows usage of labels as table, labels as vector and caching of Counter
# instances by the user as well as shortcuts through the options directly.
#
#     $ curl -sf http://localhost:4243/metrics | grep intel_matches
#     # HELP zeek_intel_matches_total Zeek Script Metric
#     # TYPE zeek_intel_matches_total counter
#     zeek_intel_matches_total{endpoint="",indicator_type="intel::domain"} 25.000000 1656951295319
#     zeek_intel_matches_total{endpoint="",indicator_type="intel::url"} 5.000000 1656951295319
#     zeek_intel_matches_total{endpoint="",indicator_type="intel::addr"} 5.000000 1656951295319

@load base/frameworks/intel
@load policy/frameworks/intel/seen

global intel_matches_cf = Telemetry::register_counter([
	$prefix="zeek",
	$name="intel_matches",
	$unit="1",
	$labels=vector("indicator_type")
]);

global intel_matches_counter_cache: table[string] of Telemetry::Counter;

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	print(fmt("Intel::match: %s %s items=%s", s$indicator, s$indicator_type, |items|));
	local indicator_type = to_lower(cat(s$indicator_type));
	local c1 = Telemetry::counter_with(intel_matches_cf, table(["indicator_type"] = indicator_type));
	Telemetry::counter_inc(c1);

	# A bit more succinct than constructing a full table.
	local c2 = Telemetry::counter_with_v(intel_matches_cf, vector(indicator_type));
	Telemetry::counter_inc(c2);

	# User-side cached version of counters.
	#
	# We could do transparent caching in the Telemetry module,
	# but maybe for now leave it out and put the burden on the
	# user for high-frequency events (if that's actually needed).
	if ( indicator_type !in intel_matches_counter_cache )
		intel_matches_counter_cache[indicator_type] = Telemetry::counter_with_v(intel_matches_cf, vector(indicator_type));
	local c3 = intel_matches_counter_cache[indicator_type];
	Telemetry::counter_inc(c3);

	# Shortcut via CounterOpts directly.
	Telemetry::counter_opts_inc(
		[$prefix="zeek", $name="intel_matches", $unit="1", $labels=vector("indicator_type")],
		table(["indicator_type"] = indicator_type)
	);

	Telemetry::counter_opts_inc_v(
		[$prefix="zeek", $name="intel_matches", $unit="1", $labels=vector("indicator_type")],
		vector(indicator_type)
	);

	}

# Example: Expose how many indicator types have been loaded. This
# is using Telemetry::gauge_opts_set_v() shortcut to access set
# values directly without going through intermediary objects.
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
# these numbers as stats without needing to poke at the details.

module Intel;

global intel_gauge_opts = Telemetry::GaugeOpts(
	$prefix="zeek",
	$name="intel_indicators",
	$unit="1",
	$labels=vector("indicator_type"),
	$helptext="Number of Intel indicators loaded"
);

hook Telemetry::collect()
	{
	print("Telemetry::collect() - intel");
	local g: Telemetry::Gauge;

	Telemetry::gauge_opts_set_v(intel_gauge_opts,
	                            |Intel::min_data_store$host_data|,
	                            vector("addr"));

	Telemetry::gauge_opts_set_v(intel_gauge_opts,
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
		Telemetry::gauge_opts_set_v(intel_gauge_opts, v, vector(k));
	}

module TelemetryExamples;

# Example: Expose pending timers and current connections from script land
#          as gauges, update them within the Telemetry::collect hook.
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
global current_conns_gf = Telemetry::register_gauge([
	$prefix="zeek",
	$name="current_connections",
	$unit="1",
	$helptext="Currently active connections."
]);
global current_conns_g = Telemetry::gauge_with(current_conns_gf);

global current_timers_gf = Telemetry::register_gauge([
	$prefix="zeek",
	$name="active_timers",
	$unit="1",
	$helptext="Currently active timers."
]);
global current_timers_g = Telemetry::gauge_with(current_timers_gf);

# This ends-up being zeek_timers_total on the Prometheus side.
global total_timers_cf = Telemetry::register_counter([
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
