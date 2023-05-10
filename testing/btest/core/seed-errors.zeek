# @TEST-DOC: Test specifying the same seeds via ZEEK_SEED
# @TEST-EXEC: echo "file does not exist"
# @TEST-EXEC-FAIL: ZEEK_SEED_FILE=./does/not-exist zeek -b %INPUT >> output 2>&1
# @TEST-EXEC: echo "cannot use ZEEK_SEED_FILE and ZEEK_SEED" > output
# @TEST-EXEC-FAIL: ZEEK_SEED_FILE=./does/not-exist ZEEK_SEED="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0" zeek -b %INPUT >> output 2>&1
# @TEST-EXEC: echo "wrong format (1)" >> output
# @TEST-EXEC-FAIL: ZEEK_SEED_FILE= ZEEK_SEED="a b c 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0" zeek -b %INPUT >> output 2>&1
# @TEST-EXEC: echo "wrong format (2)" >> output
# @TEST-EXEC-FAIL: ZEEK_SEED_FILE= ZEEK_SEED="0 0 0" zeek -b %INPUT >> output 2>&1

# @TEST-EXEC: btest-diff output

print rand(500000), unique_id("C");
