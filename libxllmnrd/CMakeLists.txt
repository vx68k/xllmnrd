#

add_compile_definitions(HAVE_CONFIG_H)

add_library(xllmnrdc STATIC interface.cpp rtnetlink.cpp ifaddr.cpp posix.cpp)

target_include_directories(xllmnrdc PUBLIC
    "${PROJECT_BINARY_DIR}"
)
