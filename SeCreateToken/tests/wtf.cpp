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

//#pragma comment(linker, "/export:NtCreat")

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"advapi32.lib")


using namespace std;

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
    HANDLE hCPTH;
    LUID lAuthID = SYSTEM_LUID;

    LARGE_INTEGER liExpire;
    liExpire.QuadPart = 150;


    HANDLE hCP = GetCurrentProcess();
    HANDLE hCPT;
    OpenProcessToken(hCP,TOKEN_READ,&hCPT);

    PTOKEN_USER ptuTokenUser = GTI_WRAPPER<PTOKEN_USER>(hCPT,TokenUser);
    PTOKEN_GROUPS ptgTokenGroups = GTI_WRAPPER<PTOKEN_GROUPS>(hCPT,TokenGroups);
    PTOKEN_PRIVILEGES ptpTokenPriviliges = GTI_WRAPPER<PTOKEN_PRIVILEGES>(hCPT,TokenPrivileges);
    //PTOKEN_OWNER ptoTokenOwner = GTI_WRAPPER<PTOKEN_OWNER>(hCPT, TokenOwner);
    PTOKEN_PRIMARY_GROUP ptgTokemPrimaryGroups = GTI_WRAPPER<PTOKEN_PRIMARY_GROUP>(hCPT,TokenPrimaryGroup);
    PTOKEN_SOURCE ptsTokenSource = GTI_WRAPPER<PTOKEN_SOURCE>(hCPT,TokenSource);

    NTSTATUS stat;
    stat = NtCreateToken(&hCPTH,TOKEN_ALL_ACCESS,NULL,TokenPrimary,&lAuthID,&liExpire,ptuTokenUser,ptgTokenGroups,ptpTokenPriviliges,NULL,ptgTokemPrimaryGroups,NULL,ptsTokenSource);
    wcout << "0x"<< hex << stat;

}