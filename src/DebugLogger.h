// A logger for (selective) debugging output. Only compiled in if DEBUG is
// defined.

#pragma once

#ifdef DEBUG

#include "zeek/zeek-config.h"

#include <stdio.h>
#include <set>
#include <string>

#include "zeek/RunState.h"
#include "zeek/util.h"

#define DBG_LOG(stream, ...)                                                                       \
	if ( ::zeek::detail::debug_logger.IsEnabled(stream) )                                          \
	::zeek::detail::debug_logger.Log(stream, __VA_ARGS__)
#define DBG_LOG_VERBOSE(stream, ...)                                                               \
	if ( ::zeek::detail::debug_logger.IsVerbose() &&                                               \
	     ::zeek::detail::debug_logger.IsEnabled(stream) )                                          \
	::zeek::detail::debug_logger.Log(stream, __VA_ARGS__)
#define DBG_PUSH(stream) ::zeek::detail::debug_logger.PushIndent(stream)
#define DBG_POP(stream) ::zeek::detail::debug_logger.PopIndent(stream)

#define PLUGIN_DBG_LOG(plugin, ...) ::zeek::detail::debug_logger.Log(plugin, __VA_ARGS__)

namespace zeek
	{

namespace plugin
	{
class Plugin;
	}

// To add a new debugging stream, add a constant here as well as
// an entry to DebugLogger::streams in DebugLogger.cc.

enum DebugStream
	{
	DBG_SERIAL, // Serialization
	DBG_RULES, // Signature matching
	DBG_STRING, // String code
	DBG_NOTIFIERS, // Notifiers
	DBG_MAINLOOP, // Main IOSource loop
	DBG_ANALYZER, // Analyzer framework
	DBG_PACKET_ANALYSIS, // Packet analysis
	DBG_FILE_ANALYSIS, // File analysis
	DBG_TM, // Time-machine packet input via Broccoli
	DBG_LOGGING, // Logging streams
	DBG_INPUT, // Input streams
	DBG_THREADING, // Threading system
	DBG_PLUGINS, // Plugin system
	DBG_ZEEKYGEN, // Zeekygen
	DBG_PKTIO, // Packet sources and dumpers.
	DBG_BROKER, // Broker communication
	DBG_SCRIPTS, // Script initialization
	DBG_SUPERVISOR, // Process supervisor
	DBG_HASHKEY, // HashKey buffers
	DBG_SPICY, // Spicy functionality

	NUM_DBGS // Has to be last
	};

namespace detail
	{

class DebugLogger
	{
public:
	// Output goes to stderr per default.
	DebugLogger();
	~DebugLogger();

	void OpenDebugLog(const char* filename = 0);

	template <typename... Args> void Log(DebugStream stream, const char* fmt, Args&&... args) const
		{
		Stream* g = &streams[int(stream)];

		if ( ! g->enabled )
			return;

		fprintf(file, "%17.06f/%17.06f [%s] ", run_state::network_time, util::current_time(true),
		        g->prefix);

		for ( int i = g->indent; i > 0; --i )
			fputs("   ", file);

		if constexpr ( sizeof...(args) > 0 )
			fprintf(file, fmt, std::forward<Args>(args)...);
		else
			fprintf(file, "%s", fmt);

		fputc('\n', file);
		fflush(file);
		}

	template <typename... Args>
	void Log(const plugin::Plugin& plugin, const char* fmt, Args&&... args) const
		{
		std::string tok = PluginStreamName(GetPluginName(plugin));

		if ( enabled_streams.find(tok) == enabled_streams.end() )
			return;

		fprintf(file, "%17.06f/%17.06f [plugin %s] ", run_state::network_time,
		        util::current_time(true), GetPluginName(plugin));

		if constexpr ( sizeof...(args) > 0 )
			fprintf(file, fmt, std::forward<Args>(args)...);
		else
			fprintf(file, "%s", fmt);

		fputc('\n', file);
		fflush(file);
		}

	void PushIndent(DebugStream stream) { ++streams[int(stream)].indent; }
	void PopIndent(DebugStream stream) { --streams[int(stream)].indent; }

	void EnableStream(DebugStream stream) { streams[int(stream)].enabled = true; }
	void DisableStream(DebugStream stream) { streams[int(stream)].enabled = false; }

	// Takes comma-separated list of stream prefixes.
	void EnableStreams(const char* streams);

	// Check the enabled streams for invalid ones.
	bool CheckStreams(const std::set<std::string>& plugin_names) const;

	bool IsEnabled(DebugStream stream) const { return streams[int(stream)].enabled; }

	void SetVerbose(bool arg_verbose) { verbose = arg_verbose; }
	bool IsVerbose() const { return verbose; }

	void ShowStreamsHelp() const;

private:
	FILE* file;
	bool verbose;

	struct Stream
		{
		const char* prefix;
		int indent;
		bool enabled;
		};

	std::set<std::string> enabled_streams;

	static Stream streams[NUM_DBGS];

	std::string PluginStreamName(const std::string& plugin_name) const
		{
		return "plugin-" + util::strreplace(plugin_name, "::", "-");
		}

	std::string GetPluginName(const plugin::Plugin& plugin) const;
	};

extern DebugLogger debug_logger;

	} // namespace detail
	} // namespace zeek

#else
#define DBG_LOG(...)
#define DBG_LOG_VERBOSE(...)
#define DBG_PUSH(stream)
#define DBG_POP(stream)
#define PLUGIN_DBG_LOG(plugin, ...)
#endif
