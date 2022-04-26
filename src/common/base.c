#include <windows.h>
#include "bofdefs.h"
#include "beacon.h"
#ifndef bufsize
#define bufsize 8192
#endif

//#pragma GCC diagnostic ignored "-Wint-conversion"
//formatp output = {1}; // this is just done so its we don't go into .bss which isn't handled properly
char * output = (char*)1;
WORD currentoutsize = 1;
HANDLE trash = (HANDLE)1; // Needed for x64 to not give relocation error
//#pragma GCC diagnostic pop

int bofstart();
#ifdef BOF
void internal_printf(const char* format, ...);
#endif
char * Utf16ToUtf8(const wchar_t* input);
wchar_t * Utf8ToUtf16(const char * input);
void printoutput(BOOL done);
void bofstop();


#ifdef BOF
int bofstart()
{   
    //output.original=NULL;
    //handle any global initilization here
    //BeaconFormatAlloc(&output, bufsize+256);
    output = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;

}

void internal_printf(const char* format, ...){
    int buffersize = 0;
    char * curloc = NULL;
    char* intBuffer = NULL;
    char* transferBuffer = (char*)intAlloc(bufsize);
    va_list args;
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args); // +1 because vsprintf goes to buffersize-1 , and buffersize won't return with the null
    va_end(args);
    intBuffer = (char*)intAlloc(buffersize);
    /*Print string to memory buffer*/
    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args); // tmpBuffer2 has a null terminated string
    va_end(args);
    if(buffersize + currentoutsize < bufsize) // If this print doesn't overflow our output buffer, just buffer it to the end
    {
        //BeaconFormatPrintf(&output, intBuffer);
        memcpy(output+currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else // If this print does overflow our output buffer, lets print what we have and clear any thing else as it is likely this is a large print
    {
        curloc = intBuffer;
        while(buffersize > 0)
        {
            int transfersize = 0;
            transfersize = bufsize - currentoutsize; // what is the max we could transfer this request
            if(buffersize < transfersize) //if I have less then that, lets just transfer what's left
            {
                transfersize = buffersize;
            }
            memcpy(output+currentoutsize, curloc, transfersize); // copy data into our transfer buffer
            currentoutsize += transfersize;
            //BeaconFormatPrintf(&output, transferBuffer); // copy it to cobalt strikes output buffer
            if(currentoutsize == bufsize)
            {
            printoutput(FALSE); // sets currentoutsize to 0 and prints
            }
            memset(transferBuffer, 0, transfersize); // reset our transfer buffer
            curloc += transfersize; // increment by how much data we just wrote
            buffersize -= transfersize; // subtract how much we just wrote from how much we are writing overall
        }
    }
    intFree(intBuffer);
    intFree(transferBuffer);
}

void printoutput(BOOL done)
{
    char * msg = NULL;
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    memset(output, 0, bufsize);
    if(done) {MSVCRT$free(output); output=NULL;}
}
#endif

//
// DynamicLoad
// Retrieves a function pointer given the BOF library-function name
// szBOFfunc            - The library and function name in BOF format, e.g., 
//                          KERNEL32$GetLastError
// Returns a FARPROC function pointer if successful, or NULL if lookup fails
//
FARPROC DynamicLoad(LPCSTR szBOFfunc)
{
    FARPROC fp = NULL;
    LPSTR szLibrary = NULL;
    LPSTR szFunction = NULL;
    CHAR * pchDivide = NULL;
    HMODULE hLibrary = NULL;

    szLibrary = (LPSTR)intAlloc(MSVCRT$strlen(szBOFfunc)+1);
    if(szLibrary)
    {
        MSVCRT$strcpy(szLibrary,szBOFfunc);
        pchDivide = MSVCRT$strchr(szLibrary, '$');
        pchDivide[0] = '\0';
        pchDivide++;
        szFunction = pchDivide;
        hLibrary = KERNEL32$LoadLibraryA(szLibrary);
        if (hLibrary)
        {
            fp = KERNEL32$GetProcAddress(hLibrary,szFunction);
        }
        intFree(szLibrary);
    }

    if (NULL == fp)
    {
        BeaconPrintf(CALLBACK_ERROR, "*** DynamicLoad(%s) FAILED!\n", szBOFfunc);
    }

    return fp;
}


char* Utf16ToUtf8(const wchar_t* input)
{
    int ret = KERNEL32$WideCharToMultiByte(
        CP_UTF8,
        0,
        input,
        -1,
        NULL,
        0,
        NULL,
        NULL
    );

    char* newString = (char*)intAlloc(sizeof(char) * ret);

    ret = KERNEL32$WideCharToMultiByte(
        CP_UTF8,
        0,
        input,
        -1,
        newString,
        sizeof(char) * ret,
        NULL,
        NULL
    );

    if (0 == ret)
    {
        goto fail;
    }

retloc:
    return newString;
/*location to free everything centrally*/
fail:
    if (newString){
        intFree(newString);
        newString = NULL;
    };
    goto retloc;
}

wchar_t* Utf8ToUtf16(const char* input)
{
    int ret = KERNEL32$MultiByteToWideChar(
        CP_UTF8,
        0,
        input,
        -1,
        NULL,
        0
    );

    wchar_t* newString = (wchar_t*)intAlloc(sizeof(wchar_t) * ret);

    ret = KERNEL32$MultiByteToWideChar(
        CP_UTF8,
        0,
        input,
        -1,
        newString,
        ret
    );

    if (0 == ret)
    {
        //printf("Failed to convert UNICODE string from UTF-16 to UTF-8. Last error: %d\n", (int)GetLastError());
        goto fail;
    }

retloc:
    return newString;
/*location to free everything centrally*/
fail:
    if (newString){
        intFree(newString);
        newString = NULL;
    };
    goto retloc;
}

#ifndef BOF
DWORD SetPrivilege(
    HANDLE hTokenArg,          // access token handle
    LPCSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    ) 
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    DWORD dwErrorCode = ERROR_SUCCESS;

    if ( hTokenArg )
    {
        hToken = hTokenArg;
    }
    else
    {
        // Open a handle to the access token for the calling process. That is this running program
        if( FALSE == ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))    
        {
            dwErrorCode = KERNEL32$GetLastError();
            goto SetPrivilege_end;
        }
    }
    

    if ( FALSE == ADVAPI32$LookupPrivilegeValueA( 
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        dwErrorCode = KERNEL32$GetLastError();
        goto SetPrivilege_end; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if ( FALSE == ADVAPI32$AdjustTokenPrivileges(
           hToken, 
           FALSE, 
           &tp, 
           sizeof(TOKEN_PRIVILEGES), 
           (PTOKEN_PRIVILEGES) NULL, 
           (PDWORD) NULL) )
    {
        dwErrorCode = KERNEL32$GetLastError();
        goto SetPrivilege_end; 
    } 

    // Possibly ERROR_NOT_ALL_ASSIGNED
    dwErrorCode = KERNEL32$GetLastError();

SetPrivilege_end:

    if ( !hTokenArg )
    {
        if ( hToken )
        {
            KERNEL32$CloseHandle(hToken);
            hToken = NULL;
        }
    }

    return dwErrorCode;
}
#endif

//release any global functions here
void bofstop()
{

    return;
}
