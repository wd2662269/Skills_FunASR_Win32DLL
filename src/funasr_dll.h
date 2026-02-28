/*
 * funasr_dll.h - FunASR PCM-to-Text DLL
 *
 * Architecture: x64 (matches OpenClaw node.exe)
 * Load via koffi (Node.js FFI):
 *
 *   const koffi = require('koffi');
 *   const lib = koffi.load('funasr.dll');
 *   const funasr_init    = lib.func('funasr_init',    'int',  []);
 *   const funasr_pcm     = lib.func('funasr_pcm',     'str',  ['buffer','uint32','str']);
 *   const funasr_pcm_file= lib.func('funasr_pcm_file','str',  ['str','str']);
 *   const funasr_free    = lib.func('funasr_free',     'void', ['str']);
 *   const funasr_cleanup = lib.func('funasr_cleanup',  'void', []);
 */

#ifndef FUNASR_DLL_H
#define FUNASR_DLL_H

#if defined(FUNASR_STATIC)
#define FUNASR_API
#elif defined(FUNASR_EXPORTS)
#define FUNASR_API __declspec(dllexport)
#else
#define FUNASR_API __declspec(dllimport)
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize Winsock. Call once before any funasr_pcm* calls.
 * Returns 0 on success, -1 on failure.
 */
FUNASR_API int funasr_init(void);

/*
 * Transcribe raw PCM (16kHz, mono, s16le) from memory buffer.
 *
 *   pcm_data : pointer to raw PCM samples
 *   pcm_len  : byte length of pcm_data
 *   ws_url   : FunASR WebSocket server, e.g. "ws://192.168.31.192:10090"
 *
 * Returns: heap-allocated UTF-8 string (caller must funasr_free).
 *          NULL on error.
 */
FUNASR_API const char* funasr_pcm(const uint8_t* pcm_data, uint32_t pcm_len,
                                  const char* ws_url);

/*
 * Transcribe raw PCM from file path.
 *
 *   pcm_path : path to .pcm file (s16le, 16kHz, mono)
 *   ws_url   : FunASR WebSocket server
 *
 * Returns: heap-allocated UTF-8 string (caller must funasr_free).
 */
FUNASR_API const char* funasr_pcm_file(const char* pcm_path, const char* ws_url);

/*
 * Free a string returned by funasr_pcm / funasr_pcm_file.
 */
FUNASR_API void funasr_free(const char* ptr);

/*
 * Cleanup Winsock. Call once when done.
 */
FUNASR_API void funasr_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* FUNASR_DLL_H */
