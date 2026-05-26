cmake_minimum_required(VERSION 3.25)
project(SandboxDemo VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Qt6 — set CMAKE_PREFIX_PATH to your Qt installation, e.g.:
#   cmake -DCMAKE_PREFIX_PATH="C:/Qt/6.10.0/msvc2022_64" ..
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/SandboxEngine.cpp
    src/ProcessMonitor.cpp
    src/DriverManager.cpp
)

set(HEADERS
    include/MainWindow.h
    include/SandboxEngine.h
    include/ProcessMonitor.h
    include/DriverManager.h
    include/NtDefs.h
    driver/include/SandboxIpc.h   # shared with kernel driver
)

add_executable(SandboxDemo WIN32 ${SOURCES} ${HEADERS})

target_include_directories(SandboxDemo PRIVATE
    include
    driver/include          # for SandboxIpc.h
)

target_link_libraries(SandboxDemo PRIVATE
    Qt6::Core
    Qt6::Widgets
    ntdll
    psapi
    advapi32                # SCM / registry APIs used by DriverManager
)

target_compile_options(SandboxDemo PRIVATE /W3 /wd4996)

# ---- Kernel driver is built separately with WDK ----
# See driver/CMakeLists.txt and driver/SandboxFlt.inf
# Build instructions in BUILD.md
message(STATUS "")
message(STATUS "Qt app: SandboxDemo configured.")
message(STATUS "Kernel driver: build separately — see driver/CMakeLists.txt")
message(STATUS "")
