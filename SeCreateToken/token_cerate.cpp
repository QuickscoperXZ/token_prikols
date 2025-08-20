#include <iostream>
#include <Windows.h>
#include <string>
#include <winternl.h>

#define ok "\x1b[32m\x1b[1m[+]: "
#define err "\x1b[31m\x1b[1m[-]: "
#define warn "\x1b[34m\x1b[1m[!]: "
#define trail "\x1b[!p\n"

#ifndef _NTSEAPI_H
//
// Tokens
//
/**
 * The NtCreateToken routine creates a new access token.
 *
 * @param TokenHandle Pointer to a variable that receives the handle to the newly created token.
 * @param DesiredAccess Specifies the requested access rights for the new token.
 * @param ObjectAttributes Optional pointer to an OBJECT_ATTRIBUTES structure specifying object attributes.
 * @param Type Specifies the type of token to be created (primary or impersonation).
 * @param AuthenticationId Pointer to a locally unique identifier (LUID) for the token.
 * @param ExpirationTime Pointer to a LARGE_INTEGER specifying the expiration time of the token.
 * @param User Pointer to a TOKEN_USER structure specifying the user account for the token.
 * @param Groups Pointer to a TOKEN_GROUPS structure specifying the group accounts for the token.
 * @param Privileges Pointer to a TOKEN_PRIVILEGES structure specifying the privileges for the token.
 * @param Owner Optional pointer to a TOKEN_OWNER structure specifying the owner SID for the token.
 * @param PrimaryGroup Pointer to a TOKEN_PRIMARY_GROUP structure specifying the primary group SID for the token.
 * @param DefaultDacl Optional pointer to a TOKEN_DEFAULT_DACL structure specifying the default DACL for the token.
 * @param Source Pointer to a TOKEN_SOURCE structure specifying the source of the token.
 * @return NTSTATUS code indicating success or failure.
 * @sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatetoken
 */
extern "C"
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateToken(
    _Out_ PHANDLE TokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ TOKEN_TYPE Type,
    _In_ PLUID AuthenticationId,
    _In_ PLARGE_INTEGER ExpirationTime,
    _In_ PTOKEN_USER User,
    _In_ PTOKEN_GROUPS Groups,
    _In_ PTOKEN_PRIVILEGES Privileges,
    _In_opt_ PTOKEN_OWNER Owner,
    _In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
    _In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
    _In_ PTOKEN_SOURCE Source
    );
#endif

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"advapi32.lib")

using namespace std;

void show_debug_msg(string sOutputCode, string sMessage, bool bIncludeLastError = 0)
{
    if (bIncludeLastError == 1)
    {
        cout << sOutputCode << sMessage << "Last Error: " << GetLastError() << trail;
    }
    else
    {
        cout << sOutputCode << sMessage << trail;
    }
}

PTOKEN_PRIVILEGES GTP_wrapper(HANDLE hTokenHandle)
{
    unsigned long dwLength = 0;
    GetTokenInformation(hTokenHandle, TokenPrivileges, nullptr, 0, &dwLength);

    PTOKEN_PRIVILEGES ptpTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(dwLength);

    if (GetTokenInformation(hTokenHandle, TokenPrivileges, ptpTokenPrivileges, dwLength, &dwLength) == 0)
    {
        show_debug_msg(err, "An error occured. ", 1);
        return nullptr;
    }
    else
    {
        show_debug_msg(ok, "Got token data.");
        return ptpTokenPrivileges;
    }
}

template <typename return_type>
return_type GTI_WRAPPER(HANDLE tokenHandle, _TOKEN_INFORMATION_CLASS tokenDataType){
    unsigned long dwSize = 0;
    GetTokenInformation(tokenHandle,tokenDataType,nullptr,dwSize,&dwSize);
    return_type pTokenReturnData = (return_type)malloc(dwSize);
    GetTokenInformation(tokenHandle,tokenDataType,pTokenReturnData,dwSize,&dwSize);
    return pTokenReturnData;
}

int main(int argc, char *argv[])
{
    if (argc == 1)
    {
        show_debug_msg(warn, "No arguments were provided.");
    }

    show_debug_msg(warn, "Reading current token...");

    HANDLE hCurrentProcessHnd = GetCurrentProcess();
    show_debug_msg(ok, "Got handle.");

    HANDLE hTokenHandle = NULL;
    if (OpenProcessToken(hCurrentProcessHnd, TOKEN_READ, &hTokenHandle) == 0)
    {
        show_debug_msg(err, "An error occured. ", 1);
        // return 1;
    }
    else
    {
        show_debug_msg(ok, "Token handle aquired.");
    }

    // TOKEN_PRIVILEGES tpPrivilegesBuff = TOKEN_PRIVILEGES();
    // DWORD dwPrivilegesSize = NULL;

    PTOKEN_PRIVILEGES ptpTokenPrivieleges = GTP_wrapper(hTokenHandle);

    // if (GetTokenInformation(hTokenHandle,TokenPrivileges,&tpPrivilegesBuff,0,&dwPrivilegesSize) == 0){
    // show_debug_msg(err, "An error occured. ", 1);
    // //return 1;
    // }
    // else{show_debug_msg(ok,"Token privileges aquired.");}

    show_debug_msg(warn, "Token privileges:");
    // LPWSTR ptr = &output[0];
    bool bEnoughPrivileges = false;
    for (int i = 0; i < ptpTokenPrivieleges->PrivilegeCount; i++)
    {
        WCHAR output[128];
        DWORD output_size = ARRAYSIZE(output);
        LookupPrivilegeNameW(NULL, &ptpTokenPrivieleges->Privileges[i].Luid, output, &output_size);
        wcout << warn << output << ": LUID:" << ptpTokenPrivieleges->Privileges[i].Luid.HighPart << ptpTokenPrivieleges->Privileges[i].Luid.LowPart << trail;
        
        if (output == L"SeCreateTokenPrivilege"){
            bEnoughPrivileges = true;
        }
    }

    if (bEnoughPrivileges != true){
        return 1;
    }

    PTOKEN_USER p

}