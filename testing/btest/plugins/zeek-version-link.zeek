# @TEST-DOC: Poking at internals: Expect an undefined zeek_version_X_Y_Z_plugin symbol in the plugin's .so/.dynlib. If this test turns out to be brittle, remove it.
# @TEST-REQUIRES: nm --version
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/pktsrc-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: nm -u build/lib/Demo-Foo* | sed -n -r 's/\s*([a-zA-Z]+)\s*(zeek_version)_[0-9]+_[0-9]_[0-9]+_plugin.*/\1 \2_X_Y_Z_plugin/p' > output || true
# @TEST-EXEC: btest-diff output
