module Telemetry;

export {
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

	type CounterVec: record {
		__family: opaque of dbl_counter_metric_family;
		__labels: vector of string;
	};

	type Counter: record {
		__metric: opaque of dbl_counter_metric;
	};

	global register_counter: function(opts: CounterOpts): CounterVec;

	global counter_with: function(cv: CounterVec, labels: table[string] of string &default=table()): Counter;

	## Convenience function to use label values from an array
	##
	## TODO/TBD:I Wonder if this should be the short version, rather than
	##          the table one. Could also allow a transparent cache using
	##          the vector values.
	global counter_with_values: function(cv: CounterVec, label_values: vector of string &default=vector()): Counter;

	## Increment counter by amount.
	global counter_inc: function(c: Counter, amount: double &default=1.0): bool;


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

	type GaugeVec: record {
		__family: opaque of dbl_gauge_metric_family;
		__labels: vector of string;
	};

	type Gauge: record {
		__metric: opaque of dbl_gauge_metric;
	};

	global register_gauge: function(opts: GaugeOpts): GaugeVec;

	global gauge_with: function(gv: GaugeVec, labels: table[string] of string &default=table()): Gauge;

	## Convenience function to use label values from an array
	global gauge_with_values: function(gv: GaugeVec, label_values: vector of string &default=vector()): Gauge;

	## Modify gauges.
	global gauge_inc: function(g: Gauge, amount: double &default=1.0): bool;
	global gauge_dec: function(g: Gauge, amount: double &default=1.0): bool;
	global gauge_set: function(g: Gauge, value: double): bool;

	## Collection hook. This hook is invoked every on every
	## collect_interval and allows users to update their
	## metrics.
	##
	## Implementations should be light-weight, collect() may be called
	## at high-frequencies.
	##
	## TBD: Add a parameter (for output)for future extensibility even
	## if it's not used right now. Or, have collect2() then.
	global collect: hook();

	## Could also see a collect() hook in the future that has an output
	## parameter so implementors would yield metrics rather than setting
	## values on instances.

	## Interval in which the collect hook is invoked.
	option collect_interval = 10sec;
}


## Internal helper to create the labels table.
function make_labels(keys: vector of string, values: vector of string): table[string] of string
	{
	local labels: table[string] of string;
	for ( i in keys )
		labels[keys[i]] = values[i];

	return labels;
	}

function register_counter(opts: CounterOpts): CounterVec
	{
	local f = Telemetry::__dbl_counter_family(
		opts$prefix,
		opts$name,
		opts$labels,
		opts$helptext,
		opts$unit,
		opts$is_total  # is_sum
	);
	return CounterVec($__family=f, $__labels=opts$labels);
	}

# Fallback Counter returned when there are issues with the labels.
global error_counter_cv = register_counter([
	$prefix="zeek",
	$name="telemetry_counter_usage_error",
	$unit="1",
	$helptext="This counter is returned when label usage of counters is wrong. Check reporter.log if non-zero."
]);

function counter_with(cv: CounterVec, labels: table[string] of string): Counter
	{

	# We could pre-check in script land that labels agree, but the
	# Telemetry subsystem will do it, too.
	local m = Telemetry::__dbl_counter_metric_get_or_add(cv$__family, labels);

	return Counter($__metric=m);
	}

function counter_with_values(cv: CounterVec, label_values: vector of string): Counter
	{
	if ( |cv$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |cv$__labels|, |label_values|));
		return counter_with(error_counter_cv);
		}

	return counter_with(cv, make_labels(cv$__labels, label_values));
	}


function counter_inc(c: Counter, amount: double &default=1.0): bool
	{
	return Telemetry::__dbl_counter_inc(c$__metric, amount);
	}


function register_gauge(opts: GaugeOpts): GaugeVec
	{
	local f = Telemetry::__dbl_gauge_family(
		opts$prefix,
		opts$name,
		opts$labels,
		opts$helptext,
		opts$unit,
		opts$is_total  # is_sum
	);

	return GaugeVec($__family=f, $__labels=opts$labels);
	}

# Fallback Gauge returned when there are issues with the label usage.
global error_gauge_cv = register_gauge([
	$prefix="zeek",
	$name="telemetry_gauge_usage_error",
	$unit="1",
	$helptext="This gauge is returned when label usage for gauges is wrong. Check reporter.log if non-zero."
]);

function gauge_with(gv: GaugeVec, labels: table[string] of string): Gauge
	{
	local m = Telemetry::__dbl_gauge_metric_get_or_add(gv$__family, labels);
	return Gauge($__metric=m);
	}

function gauge_with_values(gv: GaugeVec, label_values: vector of string): Gauge
	{
	if ( |gv$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |gv$__labels|, |label_values|));
		return gauge_with(error_gauge_cv);
		}

	return gauge_with(gv, make_labels(gv$__labels, label_values));
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

# Globally construct the CounterVec type. Concrete instances are created
# via Telemetry::counter_with_values().
global conn_by_service_cv = Telemetry::register_counter([
	$prefix="zeek",
	$name="connection_services",
	$unit="1",
	$labels=vector("protocol", "service")
]);

# The creation of the Counter objects here is heavy. We could add a
# custom caching table with key "<proto>-<service>" or indexed by
# a label vector table[vector of string] of Counter or so.
event connection_state_remove(c: connection)
	{
	if ( |c$service| == 0 )
		{
		print(fmt("Unknown %s", c$id));
		local cx = Telemetry::counter_with_values(conn_by_service_cv, vector(cat(c$conn$proto), "unknown"));
		Telemetry::counter_inc(cx);
		}

	for (s in c$service)
		{
		print(fmt("%s %s", s, c$id));
		local cy = Telemetry::counter_with_values(conn_by_service_cv, vector(cat(c$conn$proto), to_lower(s)));
		Telemetry::counter_inc(cy);
		}
	}


# Example: Tracking intel matches by indicator_type of Seen within Intel::match()
#
# Shows usage of labels as table, labels as vector and caching of Counter
# instances by the user.
@load base/frameworks/intel
global intel_matches_cv = Telemetry::register_counter([
	$prefix="zeek",
	$name="intel",
	$unit="matches",  ## Not sure if this is a good unit.
	$labels=vector("indicator_type")
]);

global intel_matches_counter_cache: table[string] of Telemetry::Counter;

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	local indicator_type = to_lower(cat(s$indicator_type));
	local c1 = Telemetry::counter_with(intel_matches_cv, table(["indicator_type"] = indicator_type));
	Telemetry::counter_inc(c1);

	# A bit more succinct than constructing a full table.
	local c2 = Telemetry::counter_with_values(intel_matches_cv, vector(indicator_type));
	Telemetry::counter_inc(c2);

	# User-side cached version of counters.
	#
	# TBD: We could do transparent caching in the Telemetry module,
	#      but maybe for now leave it out and put the burden on the
	#      user for high-frequency events.
	if ( indicator_type !in intel_matches_counter_cache )
		intel_matches_counter_cache[indicator_type] = Telemetry::counter_with_values(intel_matches_cv, vector(indicator_type));
	local c3 = intel_matches_counter_cache[indicator_type];
	Telemetry::counter_inc(c3);
	}


# Example: Expose pending timers and current connections from script land
#          as gauges, update them within the Telemetry::collect hook.
#
# TBD: Neither metric below has labels, so this is a bit verbose with the
#      extra GaugeVector. Maybe register_gauge_vec() and special
#      case register_gauge() to return a Gauge directly.
#
#    $ curl -s localhost:4243/metrics | grep ^zeek_current
#    zeek_current_timers{endpoint=""} 139.000000 1656667176875
#    zeek_current_connections{endpoint=""} 59.000000 1656667176875
#
global current_conns_gv = Telemetry::register_gauge([
	$prefix="zeek",
	$name="current_connections",
	$unit="1"
]);
global current_conns_g = Telemetry::gauge_with(current_conns_gv);

global current_timers_gv = Telemetry::register_gauge([
	$prefix="zeek",
	$name="current_timers",
	$unit="1"
]);
global current_timers_g = Telemetry::gauge_with(current_timers_gv);

hook Telemetry::collect()
	{
	print("Telemetry::collect()");
	local cs = get_conn_stats();
	Telemetry::gauge_set(current_conns_g, cs$current_conns);
	local ts = get_timer_stats();
	Telemetry::gauge_set(current_timers_g, ts$current);
	}
