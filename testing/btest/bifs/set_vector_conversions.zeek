# @TEST-DOC: tests the vector_to_set and set_to_vector BIFs
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

print("vector to set");
local v1 = vector(1, 1, 1, 2, 2, 3, 3, 4);
local s1 = vector_to_set(v1);
print(v1);
print(s1);

print("");
print("set to vector (count)");
local s2 = set(1, 2, 3, 4);
local v2 = set_to_vector(s2);
print(s2);
print(v2);

print("");
print("set to vector (port)");
local s3 = set(21/tcp, 23/tcp);
local v3 = set_to_vector(s3);
print(s3);
print(v3);

print("");
print("set to vector (error with multiple index types)");
local s4: set[port, string] = { [21/tcp, "ftp"], [23/tcp, "telnet"] };
local v4 = set_to_vector(s4);
print(v4);
