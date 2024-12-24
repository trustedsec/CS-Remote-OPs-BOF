#include <windows.h>
#include <stdio.h>
#include <lmaccess.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"


DWORD DelUserFromDomainGroup(LPCWSTR lpswzServer, LPCWSTR lpswzUserName, LPCWSTR lpswzGroupName)
{
	NET_API_STATUS dwErrorCode = NERR_Success;
	dwErrorCode = NETAPI32$NetGroupDelUser(lpswzServer, lpswzGroupName, lpswzUserName);
	return dwErrorCode;
}

DWORD DelUserFromLocalGroup(LPCWSTR lpswzServer, LPCWSTR lpswzUserName, LPCWSTR lpswzGroupName, LPCWSTR lpswzDomainName)
{
	NET_API_STATUS dwErrorCode = NERR_Success;
	LOCALGROUP_MEMBERS_INFO_3 mi[1] = {0}; // https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-localgroup_members_info_3
	mi[0].lgrmi3_domainandname = intAlloc(1024);
	if (lpswzDomainName != NULL)
	{
		MSVCRT$wcscat(mi[0].lgrmi3_domainandname, lpswzDomainName);
		MSVCRT$wcscat(mi[0].lgrmi3_domainandname, L"\\");
	}
	MSVCRT$wcscat(mi[0].lgrmi3_domainandname, lpswzUserName);
	dwErrorCode = NETAPI32$NetLocalGroupDelMembers(lpswzServer, lpswzGroupName, 3, (LPBYTE)mi, 1); 
	return dwErrorCode;
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	datap parser = {0};
	BeaconDataParse(&parser, Buffer, Length);
	LPCWSTR lpswzDomainName = (LPCWSTR)BeaconDataExtract(&parser, NULL); // $5
	LPCWSTR lpswzHostName = (LPCWSTR)BeaconDataExtract(&parser, NULL); // $4
	LPCWSTR lpswzUserName = (LPCWSTR)BeaconDataExtract(&parser, NULL); // $2
	LPCWSTR lpswzGroupName = (LPCWSTR)BeaconDataExtract(&parser, NULL);// $3
	if(lpswzHostName[0] == L'\0'){lpswzHostName = NULL;}
	if(lpswzDomainName[0] == L'\0'){lpswzDomainName = NULL;}

	if(!bofstart())
	{
		return;
	}

	if (lpswzDomainName == NULL && lpswzHostName != NULL)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "Removing %S from %S\n", lpswzUserName, lpswzGroupName);
		dwErrorCode = DelUserFromDomainGroup(lpswzHostName, lpswzUserName, lpswzGroupName);
		if ( ERROR_SUCCESS != dwErrorCode )
		{
			BeaconPrintf(CALLBACK_ERROR, "Removing user from domain group failed: %lX\n", dwErrorCode); 
			goto go_end; 
		}
	}
	else if (lpswzHostName == NULL)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "Removing %S from local group %S\n", lpswzUserName, lpswzGroupName);
		dwErrorCode = DelUserFromLocalGroup(lpswzHostName, lpswzUserName, lpswzGroupName, lpswzDomainName);
		if (ERROR_SUCCESS != dwErrorCode) 
		{
			BeaconPrintf(CALLBACK_ERROR, "Unable to remove user to local group %lX\n", dwErrorCode);
			goto go_end;
		}
	}
	internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);
	bofstop();
};
#else
#define TEST_USERNAME L"localadmin2"
#define TEST_HOSTNAME L""
#define TEST_GROUPNAME L"Remote Desktop Users"
#define TEST_DOMAIN L"WOOT"

int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	LPCWSTR lpswzHostName = TEST_HOSTNAME;
	LPCWSTR lpswzUserName = TEST_USERNAME;
	LPCWSTR lpswzGroupName = TEST_GROUPNAME;
	LPCWSTR lpswzDomainName = TEST_DOMAIN;
	
	internal_printf("Removing %S from %S\n", lpswzUserName, lpswzGroupName);

	dwErrorCode = DelUserFromLocalGroup(lpswzHostName, lpswzUserName, lpswzGroupName, lpswzDomainName);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "Removing user from group failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:
	return dwErrorCode;
}
#endif