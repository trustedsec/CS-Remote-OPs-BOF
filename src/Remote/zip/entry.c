#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

#ifndef BOF
#  include <stdio.h>
#  include <stdarg.h>
static void internal_printf(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
}
static void BeaconPrintf(int t, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
}
#endif

// CRC-32 implementation for ZIP encryption and integrity checks.
static DWORD crc32_step(DWORD crc, BYTE c)
{
    int i;
    crc ^= (DWORD)c;
    for (i = 0; i < 8; i++)
        crc = (crc >> 1) ^ (0xEDB88320UL & (DWORD)(0UL - (crc & 1UL)));
    return crc;
}

static DWORD crc32_buf(const BYTE *buf, DWORD len)
{
    DWORD crc = 0xFFFFFFFFUL;
    DWORD i;
    for (i = 0; i < len; i++)
        crc = crc32_step(crc, buf[i]);
    return crc ^ 0xFFFFFFFFUL;
}

typedef struct { DWORD k0, k1, k2; } ZipKeys;

static void zip_keys_init(ZipKeys *z, const char *pw)
{
    z->k0 = 305419896UL;
    z->k1 = 591751049UL;
    z->k2 = 878082192UL;
    while (*pw) {
        z->k0 = crc32_step(z->k0, (BYTE)*pw);
        z->k1 = (z->k1 + (z->k0 & 0xFF)) * 134775813UL + 1UL;
        z->k2 = crc32_step(z->k2, (BYTE)(z->k1 >> 24));
        pw++;
    }
}

static BYTE zip_enc(ZipKeys *z, BYTE plain)
{
    DWORD tmp = z->k2 | 2UL;
    BYTE  t   = (BYTE)(((tmp * (tmp ^ 1UL)) >> 8) & 0xFF);
    z->k0 = crc32_step(z->k0, plain);
    z->k1 = (z->k1 + (z->k0 & 0xFF)) * 134775813UL + 1UL;
    z->k2 = crc32_step(z->k2, (BYTE)(z->k1 >> 24));
    return t ^ plain;
}

// Growable heap buffer
typedef struct { BYTE *data; DWORD size; DWORD cap; } Buf;

static BOOL buf_init(Buf *b, DWORD cap)
{
    b->data = (BYTE *)intAlloc(cap);
    if (!b->data) return FALSE;
    b->size = 0; b->cap = cap;
    return TRUE;
}

static void buf_free(Buf *b)
{
    if (b->data) { intFree(b->data); b->data = NULL; }
    b->size = b->cap = 0;
}

static BOOL buf_ensure(Buf *b, DWORD extra)
{
    BYTE *nd;
    DWORD nc;
    if (b->size + extra <= b->cap) return TRUE;
    nc = b->cap + extra + 65536;
    nd = (BYTE *)intRealloc(b->data, nc);
    if (!nd) return FALSE;
    b->data = nd; b->cap = nc;
    return TRUE;
}

static BOOL buf_append(Buf *b, const BYTE *src, DWORD n)
{
    if (!buf_ensure(b, n)) return FALSE;
    MSVCRT$memcpy(b->data + b->size, src, n);
    b->size += n;
    return TRUE;
}

static BOOL buf_u16(Buf *b, WORD v)
{
    BYTE t[2];
    t[0] = (BYTE)(v);
    t[1] = (BYTE)(v >> 8);
    return buf_append(b, t, 2);
}

static BOOL buf_u32(Buf *b, DWORD v)
{
    BYTE t[4];
    t[0] = (BYTE)(v);
    t[1] = (BYTE)(v >> 8);
    t[2] = (BYTE)(v >> 16);
    t[3] = (BYTE)(v >> 24);
    return buf_append(b, t, 4);
}

#define MAX_ENTRIES 1024

typedef struct {
    char  name[260];    /* stored filename (base name only) */
    WORD  name_len;
    DWORD offset;       /* byte offset of the local file header in buf */
    DWORD crc32;
    DWORD comp_size;    /* compressed size (plain + 12 if encrypted)   */
    DWORD uncomp_size;
    WORD  flags;        /* 0x0001 = encrypted                           */
} ZipEntry;

// Write a file entry to the buffer, including the local file header and file data (optionally encrypted).
static BOOL zip_write_entry(Buf *b, ZipEntry *e,
                             const BYTE *fdata, DWORD flen,
                             const char *pw)
{
    BYTE  *enc      = NULL;
    DWORD  comp_size;
    WORD   flags    = 0;
    DWORD  i;

    e->crc32       = crc32_buf(fdata, flen);
    e->uncomp_size = flen;
    e->offset      = b->size;

    if (pw && pw[0]) {
        // Encrypt the file data in a separate buffer, since we need the comp_size before writing the LFH.
        flags     = 0x0001;
        comp_size = flen + 12;

        enc = (BYTE *)intAlloc(comp_size);
        if (!enc) return FALSE;

        {
            ZipKeys z;
            zip_keys_init(&z, pw);
            MSVCRT$srand((unsigned int)KERNEL32$GetTickCount());

            for (i = 0; i < 11; i++)
                enc[i] = zip_enc(&z, (BYTE)(MSVCRT$rand() & 0xFF));

            enc[11] = zip_enc(&z, (BYTE)(e->crc32 >> 24));

            for (i = 0; i < flen; i++)
                enc[12 + i] = zip_enc(&z, fdata[i]);
        }
    } else {
        comp_size = flen;
    }

    e->comp_size = comp_size;
    e->flags     = flags;

    // Local file header: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
    buf_u32(b, 0x04034b50UL);   /* LFH signature    */
    buf_u16(b, 20);              /* version needed   */
    buf_u16(b, flags);           /* general purpose  */
    buf_u16(b, 0);               /* method: STORE    */
    buf_u16(b, 0);               /* last mod time    */
    buf_u16(b, 0);               /* last mod date    */
    buf_u32(b, e->crc32);
    buf_u32(b, comp_size);
    buf_u32(b, flen);
    buf_u16(b, e->name_len);
    buf_u16(b, 0);               /* extra field len  */
    buf_append(b, (BYTE *)e->name, e->name_len);

    if (enc) {
        buf_append(b, enc, comp_size);
        intFree(enc);
    } else {
        buf_append(b, fdata, flen);
    }

    return TRUE;
}

// Build central directory and end-of-central-directory records, and append to the buffer.
static void zip_finalize(Buf *b, ZipEntry *entries, DWORD count)
{
    DWORD i;
    DWORD cd_start = b->size;

    for (i = 0; i < count; i++) {
        ZipEntry *e = &entries[i];
        buf_u32(b, 0x02014b50UL);   /* CDH signature      */
        buf_u16(b, 20);              /* version made by    */
        buf_u16(b, 20);              /* version needed     */
        buf_u16(b, e->flags);
        buf_u16(b, 0);               /* method: STORE      */
        buf_u16(b, 0);               /* last mod time      */
        buf_u16(b, 0);               /* last mod date      */
        buf_u32(b, e->crc32);
        buf_u32(b, e->comp_size);
        buf_u32(b, e->uncomp_size);
        buf_u16(b, e->name_len);
        buf_u16(b, 0);               /* extra field len    */
        buf_u16(b, 0);               /* file comment len   */
        buf_u16(b, 0);               /* disk number start  */
        buf_u16(b, 0);               /* internal attrs     */
        buf_u32(b, 0);               /* external attrs     */
        buf_u32(b, e->offset);       /* LFH offset         */
        buf_append(b, (BYTE *)e->name, e->name_len);
    }

    {
        DWORD cd_size = b->size - cd_start;
        buf_u32(b, 0x06054b50UL);        /* EOCD signature  */
        buf_u16(b, 0); buf_u16(b, 0);   /* disk numbers    */
        buf_u16(b, (WORD)count);
        buf_u16(b, (WORD)count);
        buf_u32(b, cd_size);
        buf_u32(b, cd_start);
        buf_u16(b, 0);                   /* comment length  */
    }
}

// Read an entire file into memory. Caller must intFree the returned buffer.
static BYTE *read_file(const char *path, DWORD *out_len)
{
    HANDLE hf;
    DWORD  sz, nr;
    BYTE  *buf;

    hf = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;

    sz = KERNEL32$GetFileSize(hf, NULL);
    if (sz == INVALID_FILE_SIZE) { KERNEL32$CloseHandle(hf); return NULL; }

    /* Allocate at least 1 byte so intAlloc never gets 0 */
    buf = (BYTE *)intAlloc(sz ? sz : 1);
    if (!buf) { KERNEL32$CloseHandle(hf); return NULL; }

    if (sz > 0) {
        if (!KERNEL32$ReadFile(hf, buf, sz, &nr, NULL) || nr != sz) {
            intFree(buf);
            KERNEL32$CloseHandle(hf);
            return NULL;
        }
    }

    KERNEL32$CloseHandle(hf);
    *out_len = sz;
    return buf;
}


// Get the base filename from a path
static const char *base_name(const char *path)
{
    const char *last = path;
    while (*path) {
        if (*path == '\\' || *path == '/') last = path + 1;
        path++;
    }
    return last;
}

// Ensure the output filename ends with .zip (case-insensitive). 
static char *ensure_zip_ext(const char *path)
{
    DWORD  len = (DWORD)MSVCRT$strlen(path);
    char  *out;

    /* Already ends with .zip / .ZIP / .Zip … */
    if (len >= 4 && MSVCRT$_stricmp(path + len - 4, ".zip") == 0)
        return NULL;

    out = (char *)intAlloc(len + 5); /* original + ".zip" + NUL */
    if (!out) return NULL;
    MSVCRT$strcpy(out, path);
    MSVCRT$strcat(out, ".zip");
    return out;
}

// Check if a pth is a dir.
static BOOL is_directory(const char *path)
{
    wchar_t *wpath = Utf8ToUtf16(path);
    DWORD    attrs;
    if (!wpath) return FALSE;
    attrs = KERNEL32$GetFileAttributesW(wpath);
    intFree(wpath);
    return (attrs != INVALID_FILE_ATTRIBUTES &&
            (attrs & FILE_ATTRIBUTE_DIRECTORY));
}

// Add one file with a specified archive name (including subdir if desired).
static BOOL add_file_ex(Buf *b, ZipEntry *entries, DWORD *count,
                         const char *filepath, const char *arcname,
                         const char *pw)
{
    DWORD     flen = 0;
    BYTE     *fdata;
    ZipEntry *e;
    DWORD     alen;

    if (*count >= MAX_ENTRIES) {
        internal_printf("[zip] WARNING: entry limit (%d) reached, skipping: %s\n",
                        MAX_ENTRIES, arcname);
        return TRUE; /* non-fatal */
    }

    fdata = read_file(filepath, &flen);
    if (!fdata) {
        internal_printf("[zip] WARNING: cannot read '%s' — skipping\n", filepath);
        return TRUE; /* non-fatal: skip unreadable files */
    }

    e    = &entries[*count];
    alen = (DWORD)MSVCRT$strlen(arcname);
    if (alen > 259) alen = 259;

    MSVCRT$memcpy(e->name, arcname, alen);
    e->name[alen] = '\0';
    e->name_len   = (WORD)alen;

    if (!zip_write_entry(b, e, fdata, flen, pw)) {
        intFree(fdata);
        internal_printf("[zip] ERROR: failed to write entry for '%s'\n", arcname);
        return FALSE;
    }

    intFree(fdata);
    internal_printf("[zip]   + %-42s  %lu bytes\n", arcname, (unsigned long)flen);
    (*count)++;
    return TRUE;
}

// Add one file using the base filename as the archive name (no subdir in ZIP).
static BOOL add_file(Buf *b, ZipEntry *entries, DWORD *count,
                     const char *filepath, const char *pw)
{
    return add_file_ex(b, entries, count, filepath, base_name(filepath), pw);
}

// Recursively add a directory and its contents, using arcname as the relative path inside the ZIP.
static BOOL add_directory(Buf *b, ZipEntry *entries, DWORD *count,
                           const char *dirpath, const char *prefix,
                           const char *pw, const char *out_bn)
{
    DWORD    dlen = (DWORD)MSVCRT$strlen(dirpath);
    char    *pattern;
    wchar_t *wpattern;
    WIN32_FIND_DATAW wfd;
    HANDLE   hFind;

    /* Build search pattern: dirpath + "\*" */
    pattern = (char *)intAlloc(dlen + 3);
    if (!pattern) return FALSE;
    MSVCRT$strcpy(pattern, dirpath);
    MSVCRT$strcat(pattern, "\\*");

    wpattern = Utf8ToUtf16(pattern);
    intFree(pattern);
    if (!wpattern) return FALSE;

    hFind = KERNEL32$FindFirstFileW(wpattern, &wfd);
    intFree(wpattern);
    if (hFind == INVALID_HANDLE_VALUE) return TRUE; /* empty/missing dir – non-fatal */

    do {
        char *fname, *fullpath, *arcname;
        DWORD plen, prelen, fnlen;

        /* Skip . and .. */
        if (wfd.cFileName[0] == L'.' &&
            (wfd.cFileName[1] == L'\0' ||
             (wfd.cFileName[1] == L'.' && wfd.cFileName[2] == L'\0')))
            continue;

        fname = Utf16ToUtf8(wfd.cFileName);
        if (!fname) continue;

        /* Skip the output ZIP itself */
        if (out_bn && MSVCRT$strcmp(fname, out_bn) == 0) {
            intFree(fname);
            continue;
        }

        fnlen  = (DWORD)MSVCRT$strlen(fname);
        prelen = (DWORD)MSVCRT$strlen(prefix);

        /* fullpath = dirpath + '\' + fname + NUL */
        plen     = dlen + 1 + fnlen + 1;
        fullpath = (char *)intAlloc(plen);

        /* arcname = prefix + '/' + fname + NUL */
        arcname  = (char *)intAlloc(prelen + 1 + fnlen + 1);

        if (!fullpath || !arcname) {
            if (fullpath) intFree(fullpath);
            if (arcname)  intFree(arcname);
            intFree(fname);
            continue;
        }

        MSVCRT$strcpy(fullpath, dirpath);
        MSVCRT$strcat(fullpath, "\\");
        MSVCRT$strcat(fullpath, fname);

        MSVCRT$strcpy(arcname, prefix);
        MSVCRT$strcat(arcname, "/");
        MSVCRT$strcat(arcname, fname);

        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Recurse into subdirectory */
            if (!add_directory(b, entries, count, fullpath, arcname, pw, out_bn)) {
                intFree(arcname); intFree(fullpath); intFree(fname);
                KERNEL32$FindClose(hFind);
                return FALSE;
            }
        } else {
            if (!add_file_ex(b, entries, count, fullpath, arcname, pw)) {
                intFree(arcname); intFree(fullpath); intFree(fname);
                KERNEL32$FindClose(hFind);
                return FALSE;
            }
        }

        intFree(arcname);
        intFree(fullpath);
        intFree(fname);

    } while (KERNEL32$FindNextFileW(hFind, &wfd));

    KERNEL32$FindClose(hFind);
    return TRUE;
}

DWORD ZipFiles(const char *files_arg, const char *output, const char *password)
{
    DWORD     dwErrorCode = ERROR_SUCCESS;
    Buf       buf         = {0};
    ZipEntry *entries     = NULL;
    DWORD     count       = 0;
    char     *fcopy       = NULL;
    HANDLE    hOut;
    DWORD     written;

    /* Treat empty password as no password */
    const char *pw = (password && password[0]) ? password : NULL;

    if (!buf_init(&buf, 65536)) {
        dwErrorCode = ERROR_OUTOFMEMORY;
        goto ZipFiles_end;
    }

    entries = (ZipEntry *)intAlloc(MAX_ENTRIES * sizeof(ZipEntry));
    if (!entries) {
        dwErrorCode = ERROR_OUTOFMEMORY;
        goto ZipFiles_end;
    }

    // wildcard — compress every file in the CWD 
    if (files_arg[0] == '*' && files_arg[1] == '\0') {

        WCHAR            cwd[MAX_PATH];
        WCHAR            pattern[MAX_PATH + 4];
        WIN32_FIND_DATAW wfd;
        HANDLE           hFind;
        const char      *out_bn = base_name(output); /* skip the output ZIP itself */

        if (!KERNEL32$GetCurrentDirectoryW(MAX_PATH, cwd)) {
            dwErrorCode = KERNEL32$GetLastError();
            goto ZipFiles_end;
        }

        MSVCRT$wcscpy(pattern, cwd);
        MSVCRT$wcscat(pattern, L"\\*");

        hFind = KERNEL32$FindFirstFileW(pattern, &wfd);
        if (hFind == INVALID_HANDLE_VALUE) {
            dwErrorCode = KERNEL32$GetLastError();
            goto ZipFiles_end;
        }

        do {
            char *fname, *cwdA, *fullpath;
            DWORD plen;

            /* Skip . and .. */
            if (wfd.cFileName[0] == L'.' &&
                (wfd.cFileName[1] == L'\0' ||
                 (wfd.cFileName[1] == L'.' && wfd.cFileName[2] == L'\0')))
                continue;

            fname = Utf16ToUtf8(wfd.cFileName);
            if (!fname) continue;

            /* Skip the output archive if it lives in the same directory */
            if (MSVCRT$strcmp(fname, out_bn) == 0) {
                intFree(fname);
                continue;
            }

            cwdA = Utf16ToUtf8(cwd);
            if (!cwdA) { intFree(fname); continue; }

            /* Build full path: cwd + '\' + fname + NUL */
            plen     = (DWORD)(MSVCRT$strlen(cwdA) + 1 +
                               MSVCRT$strlen(fname) + 1);
            fullpath = (char *)intAlloc(plen);
            if (fullpath) {
                MSVCRT$strcpy(fullpath, cwdA);
                MSVCRT$strcat(fullpath, "\\");
                MSVCRT$strcat(fullpath, fname);

                if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    /* Recurse: arcname prefix = dirname */
                    if (!add_directory(&buf, entries, &count,
                                       fullpath, fname, pw, out_bn)) {
                        intFree(fullpath);
                        intFree(cwdA);
                        intFree(fname);
                        KERNEL32$FindClose(hFind);
                        dwErrorCode = ERROR_WRITE_FAULT;
                        goto ZipFiles_end;
                    }
                } else {
                    if (!add_file(&buf, entries, &count, fullpath, pw)) {
                        intFree(fullpath);
                        intFree(cwdA);
                        intFree(fname);
                        KERNEL32$FindClose(hFind);
                        dwErrorCode = ERROR_WRITE_FAULT;
                        goto ZipFiles_end;
                    }
                }
                intFree(fullpath);
            }
            intFree(cwdA);
            intFree(fname);

        } while (KERNEL32$FindNextFileW(hFind, &wfd));

        KERNEL32$FindClose(hFind);

    // explicit space-separated list 
    } else {
        DWORD  alen = (DWORD)MSVCRT$strlen(files_arg);
        char  *tok;

        fcopy = (char *)intAlloc(alen + 1);
        if (!fcopy) { dwErrorCode = ERROR_OUTOFMEMORY; goto ZipFiles_end; }
        MSVCRT$strcpy(fcopy, files_arg);

        tok = MSVCRT$strtok(fcopy, " ");
        while (tok) {
            if (is_directory(tok)) {
                /* Use the last path component as the archive prefix */
                const char *dname = base_name(tok);
                /* Trim any trailing backslash so base_name works correctly */
                DWORD toklen = (DWORD)MSVCRT$strlen(tok);
                char *trimmed = NULL;
                if (toklen > 0 &&
                    (tok[toklen - 1] == '\\' || tok[toklen - 1] == '/')) {
                    trimmed = (char *)intAlloc(toklen);
                    if (trimmed) {
                        MSVCRT$memcpy(trimmed, tok, toklen - 1);
                        trimmed[toklen - 1] = '\0';
                        dname = base_name(trimmed);
                    }
                }
                if (!add_directory(&buf, entries, &count,
                                   trimmed ? trimmed : tok,
                                   dname, pw, NULL)) {
                    if (trimmed) intFree(trimmed);
                    dwErrorCode = ERROR_WRITE_FAULT;
                    goto ZipFiles_end;
                }
                if (trimmed) intFree(trimmed);
            } else {
                if (!add_file(&buf, entries, &count, tok, pw)) {
                    dwErrorCode = ERROR_WRITE_FAULT;
                    goto ZipFiles_end;
                }
            }
            tok = MSVCRT$strtok(NULL, " ");
        }
    }

    if (count == 0) {
        internal_printf("[zip] No files were added to the archive.\n");
        dwErrorCode = ERROR_FILE_NOT_FOUND;
        goto ZipFiles_end;
    }

    /* Build central directory + EOCD */
    zip_finalize(&buf, entries, count);

    /* Write ZIP to disk */
    hOut = KERNEL32$CreateFileA(output, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[zip] ERROR: cannot create '%s' (err=%lu)\n",
                        output, (unsigned long)dwErrorCode);
        goto ZipFiles_end;
    }

    written = 0;
    if (!KERNEL32$WriteFile(hOut, buf.data, buf.size, &written, NULL)) {
        dwErrorCode = KERNEL32$GetLastError();
        KERNEL32$CloseHandle(hOut);
        goto ZipFiles_end;
    }

    KERNEL32$CloseHandle(hOut);

    internal_printf("[zip] -------------------------------------------------\n");
    internal_printf("[zip] Archive : %s\n",                  output);
    internal_printf("[zip] Entries : %lu\n",   (unsigned long)count);
    internal_printf("[zip] Size    : %lu bytes\n", (unsigned long)written);
    if (pw)
        internal_printf("[zip] Encrypted (traditional PKZIP password)\n");

ZipFiles_end:
    buf_free(&buf);
    if (entries) intFree(entries);
    if (fcopy)   intFree(fcopy);
    return dwErrorCode;
}

// BOF entry point
#ifdef BOF
VOID go(
    IN PCHAR Buffer,
    IN ULONG Length)
{
    DWORD       dwErrorCode  = ERROR_SUCCESS;
    datap       parser       = {0};
    const char *files_arg    = NULL;
    const char *output_arg   = NULL;
    const char *password_arg = NULL;

    /* Pack args with: bof_pack($1, "zzz", $files, $output, $password) */
    BeaconDataParse(&parser, Buffer, Length);
    files_arg    = BeaconDataExtract(&parser, NULL);
    output_arg   = BeaconDataExtract(&parser, NULL);
    password_arg = BeaconDataExtract(&parser, NULL);

    if (!files_arg || !output_arg) {
        BeaconPrintf(CALLBACK_ERROR,
            "Usage: zip <files|*> <output.zip> [password]\n"
            "  files    : space-separated paths, or * for all CWD files\n"
            "  output   : path to the output ZIP file\n"
            "  password : optional PKZIP traditional encryption password\n");
        return;
    }

    if (!bofstart()) return;

    {
        char *output_fixed = ensure_zip_ext(output_arg);
        if (output_fixed) output_arg = output_fixed;

        internal_printf("[zip] Files  : %s\n", files_arg);
        internal_printf("[zip] Output : %s\n", output_arg);
        if (password_arg && password_arg[0])
            internal_printf("[zip] Password provided — encryption enabled\n");

        dwErrorCode = ZipFiles(files_arg, output_arg, password_arg);

        if (output_fixed) intFree(output_fixed);
    }

    if (ERROR_SUCCESS != dwErrorCode) {
        BeaconPrintf(CALLBACK_ERROR, "[zip] Failed: 0x%lX\n",
                     (unsigned long)dwErrorCode);
        goto go_end;
    }

    internal_printf("[zip] Done.\n");

go_end:
    printoutput(TRUE);
    bofstop();
}

#else
#define TEST_FILES    "C:\\Windows\\System32\\drivers\\etc\\hosts"
#define TEST_OUTPUT   "test_archive.zip"
#define TEST_PASSWORD ""

int main(int argc, char **argv)
{
    DWORD       dwErrorCode = ERROR_SUCCESS;
    const char *files    = (argc > 1) ? argv[1] : TEST_FILES;
    const char *output   = (argc > 2) ? argv[2] : TEST_OUTPUT;
    const char *password = (argc > 3) ? argv[3] : TEST_PASSWORD;
    char       *output_fixed = ensure_zip_ext(output);

    if (output_fixed) output = output_fixed;

    internal_printf("[zip] Files  : %s\n", files);
    internal_printf("[zip] Output : %s\n", output);

    dwErrorCode = ZipFiles(files, output, password);

    if (output_fixed) intFree(output_fixed);

    if (ERROR_SUCCESS != dwErrorCode) {
        internal_printf("[zip] Failed: 0x%lX\n", (unsigned long)dwErrorCode);
        goto main_end;
    }

    internal_printf("[zip] Done.\n");

main_end:
    return (int)dwErrorCode;
}
#endif
