# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output

function f(x: any)
	{
	print x;
	}

event zeek_init()
	{
	f(1);
	f("a");
	f([$a="42"]);
	}

@TEST-START-NEXT
global f: function(x: any);

event zeek_init()
	{
	local _lambda1 = function(x: any) { print "first", x; };
	local _lambda2 = function(x: any) { print "second", x; };

	f = _lambda1;
	f(1);
	f("a");

	f = _lambda2;
	f(2);
	f("b");
	}
