# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

global my_fmt = fmt;

event zeek_init() &priority=10
	{
	print "zeek_init() &priority=10";
	print my_fmt("my_fmt=%s", 1);
	}

@TEST-START-NEXT
# Runtime error due to my_fmt being assigned script_fmt and called with
# too many arguments.
global my_fmt = fmt;

function script_fmt(x: any): string
	{
	print "script_fmt", x;
	}

event zeek_init() &priority=10
	{
	print "zeek_init() &priority=10";
	if ( T )
		my_fmt = script_fmt;
	print my_fmt("my_fmt=%s", 1);
	}
