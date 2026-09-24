#include <windows.h>
#include "beacon.h"

typedef  EXECUTION_STATE (WINAPI *fpSetThreadExecutionState)(EXECUTION_STATE esFlags);

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	// $args = bof_pack($1, "zi", $string_arg, $int_arg);
	datap parser = {0};
	const char * string_arg = NULL;
	short enable = 0;
	short awake = 0;
	short away = 0;
	short display = 0;

	BeaconDataParse(&parser, Buffer, Length);
	awake = BeaconDataShort(&parser);
	away = BeaconDataShort(&parser);
	display = BeaconDataShort(&parser);
	//I'm doing something different from usual on purpose because I see so much AI code using KERNEL32$GetProcAddress / KERNEL32$LoadLibrary and I want an example showing you don't have to do that
	HANDLE hkern = GetModuleHandleA("kernel32.dll");
	fpSetThreadExecutionState fp_setThreadState = (fpSetThreadExecutionState)GetProcAddress(hkern, "SetThreadExecutionState");
	if(fp_setThreadState == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "Could not resolve the required function\n");
		return;
	}
	EXECUTION_STATE es = ES_CONTINUOUS
    | (awake   ? ES_SYSTEM_REQUIRED   : 0)
    | (away    ? ES_AWAYMODE_REQUIRED : 0)
    | (display ? ES_DISPLAY_REQUIRED  : 0);
	EXECUTION_STATE prior_es = fp_setThreadState(es);
	if(prior_es == 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to update execution state\n");
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "Updated execution state from %d to %d\n", prior_es, es);
	}
	return;

	
	

};
#else
#define TEST_STRING_ARG "TEST_STRING_ARG"
#define TEST_INT_ARG 12345
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	const char * string_arg = TEST_STRING_ARG;
	int int_arg = TEST_INT_ARG;

	internal_printf("Calling YOUNAMEHERE with arguments %s and %d\n", string_arg, int_arg );

	dwErrorCode = YOUNAMEHERE(string_arg, int_arg);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "YOUNAMEHERE failed: %lX\n", dwErrorCode);	
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:

	return dwErrorCode;
}
#endif