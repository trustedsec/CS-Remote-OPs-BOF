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
    DWORD  dwErrorCode    = ERROR_SUCCESS;
    HANDLE hFile          = INVALID_HANDLE_VALUE;
    HANDLE hChunk         = INVALID_HANDLE_VALUE;
    BYTE  *pBuffer        = NULL;
    char  *pOutPath       = NULL;
    char  *pNormPath      = NULL;
    DWORD  dwFileSize     = 0;
    DWORD  dwBytesRead    = 0;
    DWORD  dwBytesWritten = 0;
    DWORD  dwChunkIndex   = 0;
    DWORD  dwRemaining    = 0;
    DWORD  dwToRead       = 0;
    int    pathLen        = 0;
    int    lastSep        = -1;
    int    i              = 0;
    char   szBaseName[BASENAME_LEN + 1];

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

    // Allocate read buffer
    pBuffer = (BYTE *)intAlloc((DWORD)chunk_size);
    if (!pBuffer)
    {
        internal_printf("[-] FileSplit: failed to allocate %d-byte read buffer\n", chunk_size);
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        goto FileSplit_end;
    }

    // MAX_PATH (260) + slack for "<random8>_<NNNNNNNN>.bin\0"
    pOutPath = (char *)intAlloc(MAX_PATH + 32);
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

    dwFileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[-] FileSplit: GetFileSize failed: 0x%08lX\n", dwErrorCode);
        goto FileSplit_end;
    }
    if (dwFileSize == 0)
    {
        internal_printf("[-] FileSplit: source file is empty\n");
        dwErrorCode = ERROR_EMPTY;
        goto FileSplit_end;
    }

    {
        DWORD dwChunkCount = (dwFileSize + (DWORD)chunk_size - 1) / (DWORD)chunk_size;
        internal_printf("[*] Source file : %s\n",          file_path);
        internal_printf("[*] File size   : %lu byte(s)\n", dwFileSize);
        internal_printf("[*] Chunk size  : %d byte(s)\n",  chunk_size);
        internal_printf("[*] Chunks      : %lu\n",         dwChunkCount);
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

    // Split loop
    dwRemaining = dwFileSize;

    while (dwRemaining > 0)
    {
        dwToRead = (DWORD)chunk_size;
        if (dwToRead > dwRemaining)
            dwToRead = dwRemaining;

        // Read one chunk from the source
        if (!KERNEL32$ReadFile(hFile, pBuffer, dwToRead, &dwBytesRead, NULL)
            || dwBytesRead == 0)
        {
            dwErrorCode = KERNEL32$GetLastError();
            internal_printf("[-] FileSplit: ReadFile failed at chunk %lu: 0x%08lX\n",
                            dwChunkIndex, dwErrorCode);
            goto FileSplit_end;
        }

        // Build output path: <dir>\<random8>_<N>.bin
        if (lastSep >= 0)
        {
            // e.g. "C:\temp\payload.bin" -> "C:\temp\aXk3pQmR_0.bin"
            MSVCRT$_snprintf(pOutPath, MAX_PATH + 31,
                             "%.*s\\%s_%lu.bin",
                             lastSep, file_path,
                             szBaseName,
                             dwChunkIndex);
        }
        else
        {
            // No directory component -> write to current directory
            MSVCRT$_snprintf(pOutPath, MAX_PATH + 31,
                             "%s_%lu.bin",
                             szBaseName,
                             dwChunkIndex);
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

        // Write the chunk
        if (!KERNEL32$WriteFile(hChunk, pBuffer, dwBytesRead, &dwBytesWritten, NULL))
        {
            dwErrorCode = KERNEL32$GetLastError();
            internal_printf("[-] FileSplit: WriteFile failed for chunk %lu: 0x%08lX\n",
                            dwChunkIndex, dwErrorCode);
            KERNEL32$CloseHandle(hChunk);
            hChunk = INVALID_HANDLE_VALUE;
            goto FileSplit_end;
        }

        KERNEL32$CloseHandle(hChunk);
        hChunk = INVALID_HANDLE_VALUE;

        internal_printf("[+] Created: %s  (%lu byte(s))\n", pOutPath, dwBytesWritten);

        dwRemaining -= dwBytesRead;
        dwChunkIndex++;
    }

    internal_printf("[+] Done. %lu chunk(s) written.\n", dwChunkIndex);

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
