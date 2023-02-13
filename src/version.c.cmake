# configure_file(src/version.in) so we have an up-to-date version.c
# when compiling.

if ( NOT DEFINED VERSION )
	message(FATAL_ERROR "VERSION not defined")
endif ()

execute_process(COMMAND "${_PROJECT_SOURCE_DIR}/ci/collect-repo-info.py" "${ZEEK_INCLUDE_PLUGINS}"
                WORKING_DIRECTORY "${_PROJECT_SOURCE_DIR}"
                OUTPUT_VARIABLE ZEEK_BUILD_INFO
                ERROR_VARIABLE ZEEK_BUILD_INFO_ERROR
                RESULT_VARIABLE ZEEK_BUILD_INFO_RESULT
                OUTPUT_STRIP_TRAILING_WHITESPACE)

if ( NOT ZEEK_BUILD_INFO_RESULT EQUAL "0" )
    message( FATAL_ERROR "Could not collect repository info ${ZEEK_BUILD_INFO_RESULT} ${ZEEK_BUILD_INFO_ERROR}")
endif ()

# string(JSON ... ) requires CMake 3.19, but then we could do something like:
# string(JSON ZEEK_BUILD_INFO SET "${ZEEK_BUILD_INFO}"
#        compile_options cxx_flags "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}")

string(REPLACE "\"" "\\\"" ZEEK_BUILD_INFO_ESCAPED "${ZEEK_BUILD_INFO}")
string(REPLACE "\n" "\\n" ZEEK_BUILD_INFO_ESCAPED "${ZEEK_BUILD_INFO_ESCAPED}")
configure_file(${_SOURCE_DIR}/version.c.in ${_BINARY_DIR}/version.c)
