/*
 * test_main.c - Standalone test for funasr.dll
 *
 * Usage: funasr_test.exe <pcm_file> [ws://host:port]
 */

#include <stdio.h>
#include <stdlib.h>
#include "funasr_dll.h"

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcm_file> [ws://host:port]\n", argv[0]);
        return 1;
    }

    const char* pcm_path = argv[1];
    const char* ws_url   = argc > 2 ? argv[2] : "ws://192.168.31.192:10090";

    printf("FunASR DLL test\n");
    printf("  PCM: %s\n", pcm_path);
    printf("  URL: %s\n", ws_url);

    if (funasr_init() < 0) {
        fprintf(stderr, "funasr_init failed\n");
        return 1;
    }

    const char* text = funasr_pcm_file(pcm_path, ws_url);
    if (text) {
        printf("Result: %s\n", text);
        funasr_free(text);
    } else {
        fprintf(stderr, "Transcription failed\n");
        funasr_cleanup();
        return 1;
    }

    funasr_cleanup();
    return 0;
}