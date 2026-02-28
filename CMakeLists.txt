cmake_minimum_required(VERSION 3.16)
project(FunASR_DLL LANGUAGES C)

# x64 only - match OpenClaw node.exe
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Only x64 builds supported (OpenClaw node.exe is x64)")
endif()

set(CMAKE_C_STANDARD 11)

option(FUNASR_BUILD_DLL "Build funasr.dll for koffi/FFI loading" ON)
option(FUNASR_BUILD_TEST_EXE "Build standalone test executable" ON)
option(FUNASR_ENABLE_ASM "Enable x64 MASM hot paths" ON)

set(FUNASR_ASM_ENABLED OFF)
if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND FUNASR_ENABLE_ASM)
    enable_language(ASM_MASM)
    set(FUNASR_ASM_ENABLED ON)
endif()

set(FUNASR_COMMON_SOURCES
    src/funasr_dll.c
    src/iocp_coro.c
    src/ws_client.c
)

if(FUNASR_ASM_ENABLED)
    list(APPEND FUNASR_COMMON_SOURCES
        src/ws_mask_x64.asm
        src/coro_x64.asm
    )
endif()

# ===========================================================
#  Core static library (direct link for local EXE debug)
# ===========================================================
add_library(funasr_core STATIC
    ${FUNASR_COMMON_SOURCES}
)
target_include_directories(funasr_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(funasr_core PRIVATE FUNASR_STATIC)
target_link_libraries(funasr_core PUBLIC ws2_32)
if(FUNASR_ASM_ENABLED)
    target_compile_definitions(funasr_core PRIVATE FUNASR_USE_X64_ASM)
endif()

if(MSVC)
    target_compile_options(funasr_core PRIVATE
        $<$<COMPILE_LANGUAGE:C>:/W4 /O2 /GS->
    )
endif()

if(FUNASR_BUILD_DLL)
    # ===========================================================
    #  DLL target
    # ===========================================================
    add_library(funasr SHARED
        ${FUNASR_COMMON_SOURCES}
    )

    target_include_directories(funasr PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

    # Raw Winsock2 - no high-level libs
    target_link_libraries(funasr PRIVATE ws2_32)
    target_compile_definitions(funasr PRIVATE FUNASR_EXPORTS)
    if(FUNASR_ASM_ENABLED)
        target_compile_definitions(funasr PRIVATE FUNASR_USE_X64_ASM)
    endif()

    if(MSVC)
        target_compile_options(funasr PRIVATE
            $<$<COMPILE_LANGUAGE:C>:/W4 /O2 /GS->
        )
    endif()
endif()

if(FUNASR_BUILD_TEST_EXE)
    # ===========================================================
    #  Test exe (standalone debug, no OpenClaw needed)
    # ===========================================================
    add_executable(funasr_test src/test_main.c)
    target_compile_definitions(funasr_test PRIVATE FUNASR_STATIC)
    target_link_libraries(funasr_test PRIVATE funasr_core ws2_32)
endif()

# ===========================================================
#  Build:
#    cmake -B build -G "Visual Studio 17 2022" -A x64
#    cmake --build build --config Release
#
#  Output:
#    build/Release/funasr_test.exe
#    build/Release/funasr.dll (when FUNASR_BUILD_DLL=ON)
#  koffi load:
#    const lib = koffi.load('funasr.dll');
#    const funasr_pcm = lib.func('funasr_pcm', 'str',
#        ['buffer', 'uint32', 'str']);
# ===========================================================
