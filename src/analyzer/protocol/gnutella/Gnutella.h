// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::gnutella
	{

constexpr int ORIG_OK = 0x1;
constexpr int RESP_OK = 0x2;

constexpr int GNUTELLA_MSG_SIZE = 23;
constexpr int GNUTELLA_MAX_PAYLOAD = 1024;

namespace detail
	{

class GnutellaMsgState
	{
public:
	GnutellaMsgState();

	std::string buffer;
	int current_offset = 0;
	int got_CR = 0;
	std::string headers;
	char msg[GNUTELLA_MSG_SIZE] = {0};
	u_char msg_hops = 0;
	unsigned int msg_len = 0;
	int msg_pos = 0;
	int msg_sent = 1;
	u_char msg_type = 0;
	u_char msg_ttl = 0;
	char payload[GNUTELLA_MAX_PAYLOAD] = {0};
	unsigned int payload_len = 0;
	unsigned int payload_left = 0;
	};

	} // namespace detail

class Gnutella_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer
	{
public:
	explicit Gnutella_Analyzer(Connection* conn);
	~Gnutella_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new Gnutella_Analyzer(conn); }

private:
	bool NextLine(const u_char* data, int len);

	bool GnutellaOK(std::string header);
	bool IsHTTP(std::string header);

	bool Established() const { return state == (ORIG_OK | RESP_OK); }

	void DeliverLines(int len, const u_char* data, bool orig);

	void SendEvents(detail::GnutellaMsgState* p, bool is_orig);

	void DissectMessage(char* msg);
	void DeliverMessages(int len, const u_char* data, bool orig);

	int state = 0;
	int new_state = 0;
	int sent_establish = 0;

	detail::GnutellaMsgState* orig_msg_state = nullptr;
	detail::GnutellaMsgState* resp_msg_state = nullptr;
	detail::GnutellaMsgState* ms = nullptr;
	};

	} // namespace zeek::analyzer::gnutella
