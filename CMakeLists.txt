cmake_minimum_required(VERSION 3.10)
project(NoEsc)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# source files 
set(SOURCES
    src/daemon/main.cpp
    src/daemon/parser.cpp
    src/daemon/rules_engine.cpp
    src/daemon/uds_bridge.cpp
)

# header files
set(HEADERS
    src/daemon/Event.h
    src/daemon/parser.h
    src/daemon/rules_engine.h
    src/daemon/uds_bridge.h
)

# making the executables
add_executable(noesc_daemon ${SOURCES} ${HEADERS})

# directories
target_include_directories(noesc_daemon PRIVATE src/daemon)

# trigger compiler warnings
if(MSVC)
    target_compile_options(noesc_daemon PRIVATE /W4)
else()
    target_compile_options(noesc_daemon PRIVATE -Wall -Wextra)
endif()
