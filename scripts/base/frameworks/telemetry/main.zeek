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

	## Shortcut for requesting a Counter instance without exposure
	## to the intermediary CounterFamily instance.
	global counter: function(opts: CounterOpts, labels: labels_table &default=table()): Counter;

	## Shortcut for requesting a Counter instance without exposure
	## to the intermediary CounterFamily instance, using a vector
	## of label values rather than a table.
	global counter_v: function(opts: CounterOpts, label_values: labels_vector &default=vector()): Counter;

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

	## Shortcut for requesting a Gauge instance without exposure
	## to the intermediary GaugeFamily instance.
	global gauge: function(opts: GaugeOpts, labels: labels_table &default=table()): Gauge;

	## Shortcut for requesting a Gauge instance without exposure
	## to the intermediary GaugeFamily instance, using a vector
	## of label values rather than a table.
	global gauge_v: function(opts: GaugeOpts, labels: labels_vector &default=vector()): Gauge;

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

function counter(opts: CounterOpts, labels: labels_table): Counter
	{
	local cf  = register_counter(opts);
	return counter_with(cf, labels);
	}

function counter_v(opts: CounterOpts, labels: labels_vector): Counter
	{
	local cf  = register_counter(opts);
	return counter_with_v(cf, labels);
	}

function counter_inc(c: Counter, amount: double &default=1.0): bool
	{
	return Telemetry::__dbl_counter_inc(c$__metric, amount);
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

function gauge(opts: GaugeOpts, labels: labels_table): Gauge
	{
	local gf  = register_gauge(opts);
	return gauge_with(gf, labels);
	}

function gauge_v(opts: GaugeOpts, label_values: labels_vector): Gauge
	{
	local gf  = register_gauge(opts);
	return gauge_with_v(gf, label_values);
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
	if ( |c$service| == 0 )
		{
		print(fmt("Unknown %s", c$id));
		local cx = Telemetry::counter_with_v(conn_by_service_cf, vector(cat(c$conn$proto), "unknown"));
		Telemetry::counter_inc(cx);
		}

	for (s in c$service)
		{
		print(fmt("%s %s", s, c$id));
		local cy = Telemetry::counter_with_v(conn_by_service_cf, vector(cat(c$conn$proto), to_lower(s)));
		Telemetry::counter_inc(cy);
		}
	}


# Example: Tracking intel matches by indicator_type of Seen within Intel::match()
#
# Shows usage of labels as table, labels as vector and caching of Counter
# instances by the user.
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
	print(fmt("Intel::match: %s %s", s, items));
	local indicator_type = to_lower(cat(s$indicator_type));
	local c1 = Telemetry::counter_with(intel_matches_cf, table(["indicator_type"] = indicator_type));
	Telemetry::counter_inc(c1);

	# A bit more succinct than constructing a full table.
	local c2 = Telemetry::counter_with_v(intel_matches_cf, vector(indicator_type));
	Telemetry::counter_inc(c2);

	# User-side cached version of counters.
	#
	# TBD: We could do transparent caching in the Telemetry module,
	#      but maybe for now leave it out and put the burden on the
	#      user for high-frequency events.
	if ( indicator_type !in intel_matches_counter_cache )
		intel_matches_counter_cache[indicator_type] = Telemetry::counter_with_v(intel_matches_cf, vector(indicator_type));
	local c3 = intel_matches_counter_cache[indicator_type];
	Telemetry::counter_inc(c3);

	# "Shortcut" version - maybe opts wouldn't be constructed inline.
	local c4 = Telemetry::counter(
		[$prefix="zeek", $name="intel_matches", $unit="1", $labels=vector("indicator_type")],
		table(["indicator_type"] = indicator_type)
	);
	Telemetry::counter_inc(c4);

	local c5 = Telemetry::counter_v(
		[$prefix="zeek", $name="intel_matches", $unit="1", $labels=vector("indicator_type")],
		vector(indicator_type)
	);
	Telemetry::counter_inc(c4);
	}

# Example: Expose how many indicator types have been loaded. This
# is using Telemetry::gauge_v() as a shortcut to access a Gauge
# directly.
#
# Hmm, hmm. maybe Telemetry::gauge_opts_set(opts, labels_table, value)
# and Telemetry::gauge_opts_set_v(opts, labels_vector, value) would
# be the better helper, for immediate setting a value for a gauge directly
# rather than even getting the Gauge object back?
#
#    $ curl -sf http://localhost:4243/metrics | grep intel_indic
#    # HELP zeek_intel_indicators Zeek Script Metric
#    # TYPE zeek_intel_indicators gauge
#    zeek_intel_indicators{endpoint="",indicator_type="addr"} 1.000000 1656951371148
#    zeek_intel_indicators{endpoint="",indicator_type="subnet"} 2.000000 1656951371148
#    zeek_intel_indicators{endpoint="",indicator_type="domain"} 3.000000 1656951371148
#    zeek_intel_indicators{endpoint="",indicator_type="user_name"} 3.000000 1656951371148
#    zeek_intel_indicators{endpoint="",indicator_type="url"} 2.000000 1656951371148

module Intel;

global intel_gauge_opts = Telemetry::GaugeOpts(
	$prefix="zeek",
	$name="intel_indicators",
	$unit="1",
	$labels=vector("indicator_type")
);

hook Telemetry::collect()
	{
	print("Telemetry::collect() - intel");
	local g: Telemetry::Gauge;

	g = Telemetry::gauge_v(intel_gauge_opts, vector("addr"));
	Telemetry::gauge_set(g, |Intel::min_data_store$host_data|);

	g = Telemetry::gauge_v(intel_gauge_opts, vector("subnet"));
	Telemetry::gauge_set(g, |Intel::min_data_store$subnet_data|);

	# Group the string_data set by type and count.
	local counts: table[string] of count &default=0;
	for ([k, _type] in Intel::min_data_store$string_data)
		{
		# Intel::USER_NAME -> user_name
		local key = to_lower(split_string(cat(_type), /::/)[1]);
		counts[key] += 1;
		}

	for ([k], v in counts)
		{
		g = Telemetry::gauge_v(intel_gauge_opts, vector(k));
		Telemetry::gauge_set(g, v);
		}
	}

# Example: Expose pending timers and current connections from script land
#          as gauges, update them within the Telemetry::collect hook.
#
# TBD: Neither metric below has labels, so this is a bit verbose with the
#      extra GaugeFamily. Maybe register_gauge_vec() and special
#      case register_gauge() to return a Gauge directly.
#
#    $ curl -s localhost:4243/metrics | grep ^zeek_current
#    zeek_current_timers{endpoint=""} 139.000000 1656667176875
#    zeek_current_connections{endpoint=""} 59.000000 1656667176875
#
global current_conns_gf = Telemetry::register_gauge([
	$prefix="zeek",
	$name="current_connections",
	$unit="1"
]);
global current_conns_g = Telemetry::gauge_with(current_conns_gf);

global current_timers_gf = Telemetry::register_gauge([
	$prefix="zeek",
	$name="current_timers",
	$unit="1"
]);
global current_timers_g = Telemetry::gauge_with(current_timers_gf);

hook Telemetry::collect()
	{
	print("Telemetry::collect()");
	local cs = get_conn_stats();
	Telemetry::gauge_set(current_conns_g, cs$current_conns);
	local ts = get_timer_stats();
	Telemetry::gauge_set(current_timers_g, ts$current);
	}
