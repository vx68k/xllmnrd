#

add_compile_definitions(HAVE_CONFIG_H LOCALEDIR="/usr/share/locale")

add_executable(xllmnrd xllmnrd.cpp responder.cpp llmnr.c)

target_link_libraries(xllmnrd PUBLIC xllmnrdc pthread)
target_include_directories(xllmnrd PUBLIC
    "${PROJECT_BINARY_DIR}"
    "${PROJECT_SOURCE_DIR}/libxllmnrd"
)
