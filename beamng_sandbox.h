// This header needs to be force included before anything else. For that you need to modify the LUAJit buildsystem (see our luaJIT fork)
//
// How it works: it uses precompiler macros the redirect the critical syscalls to custom functions that need to be implemented by the user of the system.
//
// tl;dr: This only redirects the relevant syscalls to custom functions, you need to re-implement those in a security aware manner yourself to make sure the sandbox works
// i.e. fopen -> luab_fopen_sandboxed, implement luab_fopen_sandboxed with the same signature then
//
// only tested on windows
//
// tfischer@beamng.com, 9/2015
#pragma once

#define _CRT_TERMINATE_DEFINED // to be able to define exit()
#define _CRT_SYSTEM_DEFINED // to be able to define system()

#include <stdio.h>
#include <stdlib.h> // required here, so we do not redefine the original functions and generate duplicate definition errors

#ifdef __LUA_BEAMNG_SANDBOX_COMPILE__
// we use this block to rewrite the functions in the sandboxed application

#define fopen(...)     luab_fopen_sandboxed(__VA_ARGS__)
#define fflush(...)    luab_fflush_sandboxed(__VA_ARGS__)
#define fclose(...)    luab_fclose_sandboxed(__VA_ARGS__)
#define freopen(...)   luab_freopen_sandboxed(__VA_ARGS__)
#define setbuf(...)    luab_setbuf_sandboxed(__VA_ARGS__)
#define setvbuf(...)   luab_setvbuf_sandboxed(__VA_ARGS__)
#define fprintf(...)   luab_fprintf_sandboxed(__VA_ARGS__)
#define fscanf(...)    luab_fscanf_sandboxed(__VA_ARGS__)
#define vfprintf(...)  luab_vfprintf_sandboxed(__VA_ARGS__)
#define vfscanf(...)   luab_vfscanf_sandboxed(__VA_ARGS__)
#define fgetc(...)     luab_fgetc_sandboxed(__VA_ARGS__)
#define fgets(...)     luab_fgets_sandboxed(__VA_ARGS__)
#define fputc(...)     luab_fputc_sandboxed(__VA_ARGS__)
#define fputs(...)     luab_fputs_sandboxed(__VA_ARGS__)
#define fread(...)     luab_fread_sandboxed(__VA_ARGS__)
#define fwrite(...)    luab_fwrite_sandboxed(__VA_ARGS__)
#define fgetpos(...)   luab_fgetpos_sandboxed(__VA_ARGS__)
#define fseek(...)     luab_fseek_sandboxed(__VA_ARGS__)
#define fsetpos(...)   luab_fsetpos_sandboxed(__VA_ARGS__)
#define ftell(...)     luab_ftell_sandboxed(__VA_ARGS__)
#define rewind(...)    luab_rewind_sandboxed(__VA_ARGS__)
#define feof(...)      luab_feof_sandboxed(__VA_ARGS__)
#define ferror(...)    luab_ferror_sandboxed(__VA_ARGS__)
#define clearerr(...)  luab_clearerr_sandboxed(__VA_ARGS__)
#define _fseeki64(...) luab__fseeki64_sandboxed(__VA_ARGS__)
#define _ftelli64(...) luab__ftelli64_sandboxed(__VA_ARGS__)
#define _pclose(...)   luab__pclose_sandboxed(__VA_ARGS__)
#define _popen(...)    luab__popen_sandboxed(__VA_ARGS__)
#define tmpfile(...)   luab_tmpfile_sandboxed(__VA_ARGS__)
#define exit(...)      luab_exit_sandboxed(__VA_ARGS__)
#define getc(...)      luab_getc_sandboxed(__VA_ARGS__)
#define getenv(...)    luab_getenv_sandboxed(__VA_ARGS__)
#define putchar(...)   luab_putchar_sandboxed(__VA_ARGS__)
#define remove(...)    luab_remove_sandboxed(__VA_ARGS__)
#define rename(...)    luab_rename_sandboxed(__VA_ARGS__)
#define system(...)    luab_system_sandboxed(__VA_ARGS__)
#define tmpfile(...)   luab_tmpfile_sandboxed(__VA_ARGS__)
#define tmpnam(...)    luab_tmpnam_sandboxed(__VA_ARGS__)
#define ungetc(...)    luab_ungetc_sandboxed(__VA_ARGS__)

#define FILE void

#endif // __LUA_BEAMNG_SANDBOX_COMPILE__

#ifdef __cplusplus
extern "C" {
#define EXT_TAG
#else
#define EXT_TAG extern 
#endif //__cplusplus

#ifdef _WIN32
#define API_DECL __cdecl
#else // _WIN32
#define API_DECL
#endif // _WIN32

EXT_TAG void *   API_DECL luab_fopen_sandboxed   ( const char * filename, const char * mode );
EXT_TAG int      API_DECL luab_fclose_sandboxed ( void * stream );
EXT_TAG int      API_DECL luab_fflush_sandboxed ( void * stream );
EXT_TAG void *   API_DECL luab_freopen_sandboxed ( const char * filename, const char * mode, void * stream );
EXT_TAG void     API_DECL luab_setbuf_sandboxed ( void * stream, char * buffer );
EXT_TAG int      API_DECL luab_setvbuf_sandboxed ( void * stream, char * buffer, int mode, size_t size );
EXT_TAG int      API_DECL luab_fprintf_sandboxed ( void * stream, const char * format, ... );
EXT_TAG int      API_DECL luab_fscanf_sandboxed ( void * stream, const char * format, ... );
EXT_TAG int      API_DECL luab_vfprintf_sandboxed ( void * stream, const char * format, va_list arg );
EXT_TAG int      API_DECL luab_vfscanf_sandboxed ( void * stream, const char * format, va_list arg );
EXT_TAG int      API_DECL luab_fgetc_sandboxed ( void * stream );
EXT_TAG char *   API_DECL luab_fgets_sandboxed ( char * str, int num, void * stream );
EXT_TAG int      API_DECL luab_fputc_sandboxed ( int character, void * stream );
EXT_TAG int      API_DECL luab_fputs_sandboxed ( const char * str, void * stream );
EXT_TAG size_t   API_DECL luab_fread_sandboxed ( void * ptr, size_t size, size_t count, void * stream );
EXT_TAG size_t   API_DECL luab_fwrite_sandboxed ( const void * ptr, size_t size, size_t count, void * stream );
EXT_TAG int      API_DECL luab_fgetpos_sandboxed ( void * stream, fpos_t * pos );
EXT_TAG int      API_DECL luab_fseek_sandboxed ( void * stream, long int offset, int origin );
EXT_TAG int      API_DECL luab_fsetpos_sandboxed ( void * stream, const fpos_t * pos );
EXT_TAG long int API_DECL luab_ftell_sandboxed ( void * stream );
EXT_TAG void     API_DECL luab_rewind_sandboxed ( void * stream );
EXT_TAG int      API_DECL luab_feof_sandboxed ( void * stream );
EXT_TAG int      API_DECL luab_ferror_sandboxed ( void * stream );
EXT_TAG void     API_DECL luab_clearerr_sandboxed ( void * stream );
EXT_TAG int      API_DECL luab__fseeki64_sandboxed(void *stream, long long offset, int origin);
EXT_TAG long long API_DECL luab__ftelli64_sandboxed(void *stream);
EXT_TAG int      API_DECL luab__pclose_sandboxed(void * stream);
EXT_TAG void *   API_DECL luab__popen_sandboxed( const char *command, const char *mode );
EXT_TAG void *   API_DECL luab_tmpfile_sandboxed( void );
EXT_TAG int      API_DECL luab_getc_sandboxed( void *stream );
EXT_TAG int      API_DECL luab_putchar_sandboxed ( int character );
EXT_TAG int      API_DECL luab_remove_sandboxed ( const char * filename );
EXT_TAG int      API_DECL luab_rename_sandboxed ( const char * oldname, const char * newname );
EXT_TAG int      API_DECL luab_system_sandboxed ( const char * command );
EXT_TAG char *   API_DECL luab_tmpnam_sandboxed ( char * str );
EXT_TAG int      API_DECL luab_ungetc_sandboxed ( int character, void * stream );
EXT_TAG char *   API_DECL luab_getenv_sandboxed( const char *varname );


EXT_TAG
#ifdef _WIN32
 __declspec(noreturn)
#endif // _WIN32
void API_DECL luab_exit_sandboxed(int _Code);


#ifdef __cplusplus
}
#endif //__cplusplus
