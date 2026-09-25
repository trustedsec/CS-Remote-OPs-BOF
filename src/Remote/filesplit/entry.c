#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

#ifndef BOF
#include <stdio.h>
#include <stdlib.h>
#define internal_printf printf
static int bofstart() { return 1; }
static void printoutput(BOOL done) { (void)done; }
static void bofstop() {}
#endif

// Character set used for the random base name
static const char CHARSET[] =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789";

#define BASENAME_LEN  8
#define CHARSET_SIZE  62   /* 26 + 26 + 10 */

DWORD FileSplit(const char *file_path, int chunk_size)
{
    DWORD          dwErrorCode    = ERROR_SUCCESS;
    HANDLE         hFile          = INVALID_HANDLE_VALUE;
    HANDLE         hChunk         = INVALID_HANDLE_VALUE;
    BYTE          *pBuffer        = NULL;
    char          *pOutPath       = NULL;
    char          *pNormPath      = NULL;
    ULONGLONG      ullFileSize    = 0;
    ULONGLONG      ullRemaining   = 0;
    DWORD          dwBytesRead    = 0;
    DWORD          dwBytesWritten = 0;
    ULONGLONG      ullChunkIndex  = 0;
    DWORD          dwToRead       = 0;
    int            pathLen        = 0;
    int            lastSep        = -1;
    int            i              = 0;
    LARGE_INTEGER  liFileSize     = {0};
    int            effective_chunk_size = 0;
    char           szBaseName[BASENAME_LEN + 1];

    if (!file_path || chunk_size <= 0)
    {
        internal_printf("[-] FileSplit: invalid arguments (null path or chunk_size <= 0)\n");
        dwErrorCode = ERROR_INVALID_PARAMETER;
        goto FileSplit_end;
    }

    // Normalize the path: collapse every \\ -> \ so the printed path and
    // file operations always use single backslashes (e.g. C:\Users\... ).
    pNormPath = (char *)intAlloc(MAX_PATH + 2);
    if (!pNormPath)
    {
        internal_printf("[-] FileSplit: failed to allocate norm-path buffer\n");
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        goto FileSplit_end;
    }
    {
        const char *src = file_path;
        char       *dst = pNormPath;
        while (*src)
        {
            if (src[0] == '\\' && src[1] == '\\')
            {
                *dst++ = '\\';
                src   += 2;
            }
            else
            {
                *dst++ = *src++;
            }
        }
        *dst = '\0';
    }
    file_path = pNormPath;  /* shadow the original pointer from here on */

    // Use a small internal buffer (4KB-4MB) for I/O, independent of user chunk size
    // This allows splitting massive files into large chunks without consuming huge memory
    #define MIN_BUFFER_SIZE (4 * 1024)         /* 4 KB */
    #define DEFAULT_BUFFER_SIZE (1024 * 1024)  /* 1 MB */
    #define MAX_BUFFER_SIZE (4 * 1024 * 1024)  /* 4 MB */

    // Cap chunk_size internally to prevent unreasonable allocations
    effective_chunk_size = chunk_size;
    if (effective_chunk_size > MAX_BUFFER_SIZE)
    {
        effective_chunk_size = DEFAULT_BUFFER_SIZE;
        internal_printf("[*] FileSplit: using %d-byte internal buffer (user requested %d bytes)\n",
                        effective_chunk_size, chunk_size);
    }
    if (effective_chunk_size < MIN_BUFFER_SIZE)
    {
        effective_chunk_size = MIN_BUFFER_SIZE;
    }

    // Allocate small internal read/write buffer
    pBuffer = (BYTE *)intAlloc((DWORD)effective_chunk_size);
    if (!pBuffer)
    {
        internal_printf("[-] FileSplit: failed to allocate %d-byte internal buffer\n", effective_chunk_size);
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        goto FileSplit_end;
    }

    // Allocate buffer for output path (must fit within MAX_PATH for CreateFileA)
    // MAX_PATH is 260 chars; we reserve buffer but enforce MAX_PATH limit
    pOutPath = (char *)intAlloc(MAX_PATH + 1);
    if (!pOutPath)
    {
        internal_printf("[-] FileSplit: failed to allocate output-path buffer\n");
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        goto FileSplit_end;
    }

    // Open the source file for reading
    hFile = KERNEL32$CreateFileA(
        file_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[-] FileSplit: CreateFileA('%s') failed: 0x%08lX\n",
                        file_path, dwErrorCode);
        goto FileSplit_end;
    }

    // Use GetFileSizeEx to support files > 4GB (returns 64-bit size)
    if (!KERNEL32$GetFileSizeEx(hFile, (PLARGE_INTEGER)&liFileSize))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[-] FileSplit: GetFileSizeEx failed: 0x%08lX\n", dwErrorCode);
        goto FileSplit_end;
    }
    ullFileSize = (ULONGLONG)liFileSize.QuadPart;
    if (ullFileSize == 0)
    {
        internal_printf("[-] FileSplit: source file is empty\n");
        dwErrorCode = ERROR_EMPTY;
        goto FileSplit_end;
    }

    {
        ULONGLONG ullChunkCount = (ullFileSize + (ULONGLONG)chunk_size - 1) / (ULONGLONG)chunk_size;
        internal_printf("[*] Source file    : %s\n",           file_path);
        internal_printf("[*] File size      : %llu byte(s)\n", ullFileSize);
        internal_printf("[*] Chunk size     : %d byte(s)\n",   chunk_size);
        internal_printf("[*] Buffer size    : %d byte(s)\n",   effective_chunk_size);
        internal_printf("[*] Total chunks   : %llu\n",         ullChunkCount);
    }

    // Generate an 8-char random alphanumeric base name (once, shared by all chunks)
    MSVCRT$srand((unsigned int)KERNEL32$GetTickCount());
    for (i = 0; i < BASENAME_LEN; i++)
    {
        szBaseName[i] = CHARSET[MSVCRT$rand() % CHARSET_SIZE];
    }
    szBaseName[BASENAME_LEN] = '\0';
    internal_printf("[*] Chunk base  : %s\n", szBaseName);

    // Find the last directory separator so we can write chunks beside the source
    pathLen = (int)MSVCRT$strlen(file_path);
    for (i = pathLen - 1; i >= 0; i--)
    {
        if (file_path[i] == '\\' || file_path[i] == '/')
        {
            lastSep = i;
            break;
        }
    }

    // Split loop: for each user-specified chunk, read/write in internal buffer increments
    ullRemaining = ullFileSize;

    while (ullRemaining > 0)
    {
        // Determine how much to write to this chunk file
        ULONGLONG ullChunkRemaining = (ULONGLONG)chunk_size;
        if (ullChunkRemaining > ullRemaining)
            ullChunkRemaining = ullRemaining;

        // Build output path for this chunk: <dir>\<random8>_<N>.bin (enforce MAX_PATH limit)
        if (lastSep >= 0)
        {
            // e.g. "C:\temp\payload.bin" -> "C:\temp\aXk3pQmR_0.bin"
            int ret = MSVCRT$_snprintf(pOutPath, MAX_PATH,
                                       "%.*s\\%s_%llu.bin",
                                       lastSep, file_path,
                                       szBaseName,
                                       ullChunkIndex);
            if (ret < 0 || ret >= MAX_PATH)
            {
                internal_printf("[-] FileSplit: output path exceeds MAX_PATH (%d >= %d)\n", ret, MAX_PATH);
                dwErrorCode = ERROR_BUFFER_OVERFLOW;
                goto FileSplit_end;
            }
        }
        else
        {
            // No directory component -> write to current directory
            int ret = MSVCRT$_snprintf(pOutPath, MAX_PATH,
                                       "%s_%llu.bin",
                                       szBaseName,
                                       ullChunkIndex);
            if (ret < 0 || ret >= MAX_PATH)
            {
                internal_printf("[-] FileSplit: output path exceeds MAX_PATH (%d >= %d)\n", ret, MAX_PATH);
                dwErrorCode = ERROR_BUFFER_OVERFLOW;
                goto FileSplit_end;
            }
        }

        // Create / overwrite the chunk file
        hChunk = KERNEL32$CreateFileA(
            pOutPath,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hChunk == INVALID_HANDLE_VALUE)
        {
            dwErrorCode = KERNEL32$GetLastError();
            internal_printf("[-] FileSplit: CreateFileA('%s') failed: 0x%08lX\n",
                            pOutPath, dwErrorCode);
            goto FileSplit_end;
        }

        // Write this chunk using internal buffer-sized increments
        ULONGLONG ullChunkBytesWritten = 0;
        while (ullChunkBytesWritten < ullChunkRemaining)
        {
            // Determine how much to read in this iteration
            dwToRead = (DWORD)effective_chunk_size;
            if (dwToRead > (DWORD)(ullChunkRemaining - ullChunkBytesWritten))
                dwToRead = (DWORD)(ullChunkRemaining - ullChunkBytesWritten);

            // Read from source file
            if (!KERNEL32$ReadFile(hFile, pBuffer, dwToRead, &dwBytesRead, NULL)
                || dwBytesRead == 0)
            {
                dwErrorCode = KERNEL32$GetLastError();
                internal_printf("[-] FileSplit: ReadFile failed at chunk %llu: 0x%08lX\n",
                                ullChunkIndex, dwErrorCode);
                KERNEL32$CloseHandle(hChunk);
                hChunk = INVALID_HANDLE_VALUE;
                goto FileSplit_end;
            }

            // Write to chunk file
            if (!KERNEL32$WriteFile(hChunk, pBuffer, dwBytesRead, &dwBytesWritten, NULL))
            {
                dwErrorCode = KERNEL32$GetLastError();
                internal_printf("[-] FileSplit: WriteFile failed for chunk %llu: 0x%08lX\n",
                                ullChunkIndex, dwErrorCode);
                KERNEL32$CloseHandle(hChunk);
                hChunk = INVALID_HANDLE_VALUE;
                goto FileSplit_end;
            }

            ullChunkBytesWritten += dwBytesWritten;
            ullRemaining -= dwBytesWritten;
        }

        KERNEL32$CloseHandle(hChunk);
        hChunk = INVALID_HANDLE_VALUE;

        internal_printf("[+] Created: %s  (%llu byte(s))\n", pOutPath, ullChunkBytesWritten);

        ullChunkIndex++;
    }

    internal_printf("[+] Done. %llu chunk(s) written.\n", ullChunkIndex);

FileSplit_end:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        KERNEL32$CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    if (hChunk != INVALID_HANDLE_VALUE)
    {
        KERNEL32$CloseHandle(hChunk);
        hChunk = INVALID_HANDLE_VALUE;
    }
    if (pBuffer)
    {
        intFree(pBuffer);
        pBuffer = NULL;
    }
    if (pOutPath)
    {
        intFree(pOutPath);
        pOutPath = NULL;
    }
    if (pNormPath)
    {
        intFree(pNormPath);
        pNormPath = NULL;
    }

    return dwErrorCode;
}

// BOF entry point
#ifdef BOF
VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    DWORD       dwErrorCode = ERROR_SUCCESS;
    /*
     * Aggressor pack format:
     *   $args = bof_pack($1, "zi", $file_path, $chunk_size);
     *
     *   z  - null-terminated string  (file path on the target)
     *   i  - 32-bit signed int       (chunk size in bytes)
     */
    datap       parser      = {0};
    const char *file_path   = NULL;
    int         chunk_size  = 0;

    BeaconDataParse(&parser, Buffer, Length);
    file_path  = BeaconDataExtract(&parser, NULL);
    chunk_size = BeaconDataInt(&parser);

    if (!bofstart())
    {
        return;
    }

    internal_printf("[*] FileSplit BOF\n");
    internal_printf("[*] File path  : %s\n", file_path ? file_path : "(null)");
    internal_printf("[*] Chunk size : %d byte(s)\n", chunk_size);

    dwErrorCode = FileSplit(file_path, chunk_size);
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "FileSplit failed: 0x%08lX\n", dwErrorCode);
        goto go_end;
    }

    internal_printf("[+] SUCCESS.\n");

go_end:
    printoutput(TRUE);
    bofstop();
}

#else
#define TEST_FILE_PATH  "C:\\test\\payload.bin"
#define TEST_CHUNK_SIZE (1024 * 1024)   /* 1 MiB */

int main(int argc, char **argv)
{
    DWORD       dwErrorCode = ERROR_SUCCESS;
    const char *file_path   = TEST_FILE_PATH;
    int         chunk_size  = TEST_CHUNK_SIZE;

    if (argc >= 3)
    {
        file_path  = argv[1];
        chunk_size = atoi(argv[2]);
    }

    internal_printf("[*] FileSplit (test mode)\n");
    internal_printf("[*] File path  : %s\n", file_path);
    internal_printf("[*] Chunk size : %d byte(s)\n", chunk_size);

    dwErrorCode = FileSplit(file_path, chunk_size);
    if (ERROR_SUCCESS != dwErrorCode)
    {
        fprintf(stderr, "[-] FileSplit failed: 0x%08lX\n", dwErrorCode);
        goto main_end;
    }

    internal_printf("[+] SUCCESS.\n");

main_end:
    return (int)dwErrorCode;
}
#endif
