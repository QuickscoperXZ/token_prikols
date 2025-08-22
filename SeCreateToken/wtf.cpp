#include <iostream> //базовые потоки ввода-вывода
#include <Windows.h> //подключение Windows-API
#include <string> //Необходимо для удобного сравнения 
#include <winternl.h> //Необходимо для подключения незадокументированной части API
#include <sddl.h>
//#include <Ntdef.h>

//немного дефайнов для вывода
#define ok "\x1b[32m\x1b[1m[+]: " 
#define err "\x1b[31m\x1b[1m[-]: "
#define warn "\x1b[34m\x1b[1m[!]: "
#define trail "\x1b[!p\n"


//декларация функции NtCreateToken из ntdll. Альтернативно, эту функцию можно вызвать по ее базовому адресу.
//выглядит это примерно так:
//HANDLE hMH = GetModuleHandle("ntdll.dll");
//FARPROC fpNtCreateTokenPtr = GetProcAddress(hMh, "NtCreateToken");
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
extern "C" //ОЧЕНЬ ВАЖНО ИМЕТЬ ЭТО В ДЕКЛАРАЦИИ НА C++, ИНАЧЕ КОМПАНОВЩИК НЕ НАЙДЕТ ЕЕ!!!!
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

#pragma comment(lib,"ntdll.lib") //инфа для компоновщика
#pragma comment(lib,"advapi32.lib") //инфа для компоновщика


using namespace std; //опись неймспейса

//Функция ниже определена как шаблон, чтобы она могла принимать разные типы данных из перечисления TOKEN_INFORMATION_CLASS.
//TOKEN_INFORMATION_CLASS содержит типы данных, возвращаемых функцией GetTokenInformation.
//Подробнее: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
//https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
template <typename return_type>
return_type GTI_WRAPPER(HANDLE tokenHandle, _TOKEN_INFORMATION_CLASS tokenDataType){
    unsigned long dwSize = 0; //инициализация целевого размера структуры
    GetTokenInformation(tokenHandle,tokenDataType,nullptr,dwSize,&dwSize);  //СПЕЦИАЛЬНЫЙ БЕЗУСПЕШНЫЙ ВЫЗОВ ФУНКЦИИ. 
                                                                            //nullptr тут чтобы результат нигде не сохранялся. 
                                                                            //После вызова, функция перезаписывает dwSize переданный через указатель.
                                                                            //Это позволяет понять размер необходимой структуры

    return_type pTokenReturnData = (return_type)malloc(dwSize);             //Инициализация структуры соответсвующей структуры
                                                                            //Важно инициализировать именно так, если сделать return_type tpTokenPrivs = return_type();
                                                                            //то будет инциализирована структура единичного размера, а массивы данных в структурах - произвольного
                                                                            //Подробнее: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
    
    GetTokenInformation(tokenHandle,tokenDataType,pTokenReturnData,dwSize,&dwSize); //Получение и сохранение токена в созданную структуру.
    return pTokenReturnData; //Возврат указателя на созданную структуру
}


//Функция ниже - это враппер для функции AdjustTokenPrivilege
//Необходим как и враппер выше для создания структуры PTOKEN_PRIVILEGES необходимого размера в которую записывается предыдущие привилегии токена.

bool ATP_WRAPPER(HANDLE TokenHandle, bool DisableAll, PTOKEN_PRIVILEGES NewState){
    DWORD dwRequiredSize; //Инициализация размера
    AdjustTokenPrivileges(TokenHandle,false,NewState,0,NULL,&dwRequiredSize); //Первый неудачный запуск, чтобы получить необходимый размер 

    PTOKEN_PRIVILEGES ptpTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(dwRequiredSize); //Инициализация структуры

    if (AdjustTokenPrivileges(TokenHandle,DisableAll,NewState,dwRequiredSize,ptpTokenPrivileges,&dwRequiredSize) != 0){ //Запуск AdjustTokenPrivilege
                                                                                                                        //AdjustTokenPrivilege принимает в себя хэндл на токен и по нему заменяет структуру TOKEN_PRIVILGES, определяющей его привилегии.
                                                                                                                        //Стоит отметить, что TOKEN_PRIVILEGES позволяет только ВКЛЮЧАТЬ привилегии, а не добавлять новые
                                                                                                                        //Для новых привилегий необходимо редактировать локальные / групповые политики
                                                                                                                        //Подробнее: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
        return true;
    }
    else return false;
}

//Функция вывода всех привилегий с токена
void printAllPrivileges(HANDLE hToken){
    PTOKEN_PRIVILEGES ptpTokenPriviliges = GTI_WRAPPER<PTOKEN_PRIVILEGES>(hToken,TokenPrivileges); //Получение указателя на TOKEN_PRIVILEGES через враппер
    
    wcout << warn << "Privileges:" << trail; //wcout, так как используется LookupPrivilegeNameW, последняя буква указывает ширину символа
    for (int i = 0; i < ptpTokenPriviliges->PrivilegeCount; i++){
        WCHAR wtPrivilegeName[256]; //WCHAR для хранения результата LookupPrivilegeNameW
        DWORD dwOutputSize = ARRAYSIZE(wtPrivilegeName); //и его размер
        if (LookupPrivilegeNameW(NULL,&ptpTokenPriviliges->Privileges[i].Luid,wtPrivilegeName,&dwOutputSize) == 0) {
            wcout << err << "Something went wrong. Last Error: " << GetLastError() << trail;
        } //Непосредственно вызов функции, большинство функций в WinAPI возвращают значения через указатели, а в качестве возвращаемого значения функции используется bool, в котором 0 - возникла проблема, 1 - все ок.
        if (ptpTokenPriviliges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED){   //проверка привилегий, 
                                                                                    //так как структура LUID_AND_ATTRIBUTES в поле Privileges использует XOR нескольких значений в DWORD-е, то
                                                                                    //необходимо проверить через обычное побитовое сложение включена ли привилегия
                                                                                    //Подробнее: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew
                                                                                    //Подробнее: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid_and_attributes
            wcout << warn << wtPrivilegeName << ":\x1b[32m" << "ENABLED" << trail;
        }else {
            wcout << warn << wtPrivilegeName << ":\x1b[31m" << "DISABLED" << trail;
        }
    }
}

int main(int argc, char *argv[])
{
    LUID lAuthID = SYSTEM_LUID; //получение локального идентификатора системы, необходимого для создания токена

    LARGE_INTEGER liExpire; //Время истечения созданного токена
    liExpire.QuadPart = 150; //Указание таким образом необходимо, так как LARGE_INTEGER - это структура без конструктора


    HANDLE hCP = GetCurrentProcess(); //Хэндл на текущий процесс
    HANDLE hCPT; //Хэндл на токен
    OpenProcessToken(hCP,TOKEN_ALL_ACCESS,&hCPT);   //Получение хэндла на токен
                                                    //ВАЖНО: Для изменений токена, необходимо создать хэндл с достаточными правами.
                                                    //TOKEN_ALL_ACCESS гарантирует все права, но достаточными будут TOKEN_READ | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES

    //Далее идет использование врапперов для создания необходимых структур
    PTOKEN_PRIVILEGES ptpTokenPriviliges = GTI_WRAPPER<PTOKEN_PRIVILEGES>(hCPT,TokenPrivileges);
    

    wcout << warn << "Privileges" << trail;
    //Инициализация значений, необходимых для обнаружения SeCreateTokenPrivilege
    BOOL bCreateTokenPrivPresent = false;
    BOOL bCreateTokenPrivEnabled = false;
    int iSeCreateTokenPrivIndex = 0;
    
    //Вывод всех привилегий
    printAllPrivileges(hCPT);

    //В этом цикле происходит перебор всех привилегий в токене и их значений (вкл/выкл)
    //Для обнаружения используется string::compare, который может принимать в себя как WCHAR (wchar_t*), так и wstring,string и другие строковые объекты
    for (int i=0; i < ptpTokenPriviliges->PrivilegeCount; i++){
        WCHAR output[256];
        DWORD output_size = ARRAYSIZE(output);
        LookupPrivilegeNameW(NULL,&ptpTokenPriviliges->Privileges[i].Luid,output,&output_size);
        wstring wsComparable = output;

        if (wsComparable.compare(L"SeCreateTokenPrivilege") == 0){
            bCreateTokenPrivPresent = true;
        }

        if (ptpTokenPriviliges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED){
            if (wsComparable.compare(L"SeCreateTokenPrivilege") == 0){
                bCreateTokenPrivEnabled = true;
                iSeCreateTokenPrivIndex = i;
            }
        } 
    }

    
    if (bCreateTokenPrivEnabled & bCreateTokenPrivPresent) {
        wcout << ok << "Privilege is present and enabled. Processing fruther." << trail;
    }
    else if (bCreateTokenPrivEnabled || bCreateTokenPrivPresent){
        wcout << warn << "Privilege is present but not enabled. Enabling ALL privileges." << trail;
        
        //В этом цикле происходит перебор по привилегиям в структуре TOKEN_PRIVILEGES извлеченной из текущего основного токена процесса и изменение их значения.
        //Это позволяет создать структуру для использования в AdjustTokenPrivileges. Для перезаписи я использовал одну структуру, но в целом можно инициализировать новую.
        for (int i = 0; i < ptpTokenPriviliges->PrivilegeCount; i++){
            ptpTokenPriviliges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
        }
        //Тут осуществляется выполнение AdjustTokenPrivileges через соответствующий враппер, после чего снова выводятся привилегии.
        if (ATP_WRAPPER(hCPT,false,ptpTokenPriviliges)){
            wcout << ok << "All privileges are enabled." << trail;
            printAllPrivileges(hCPT);
        }
        else {
            wcout << err << "Something went wrong, Last Error: " << GetLastError() << trail;
        }
    }
    else {
        wcout << err << "Privilege is not present and enabled." << trail;
        return 1;
    }

    //Для вызова NtCreateToken необходимо задекларировать ее, что было сделано прежде.
    //Так же необходимо иметь SeCreateTokenPrivilege и в идеале SeAssignPrimaryPrivilege для эксплуатации
    //Это позволяет создать новый токен и назначить его новому процессу.
    HANDLE hNewTokenHandle; //Новый хэндл под новый токен
    
    //Многие незадокументированные функции и функции из WDM и ядра используют NTSTATUS для возвращения информации о результатах функции.
    //Эти статусы отличаются от тех, которые представлены в GetLastError();
    //Ниже производится инициализация NTSTATUS c помощью создания нового токена. Созданный токен по-факту является дубликатом текущего.
    //Однако, можно создать структуры TOKEN_USER, TOKEN_PRIMARY_GROUP, TOKEN_GROUP и TOKEN_PRIVILEGES на имя другого пользователя.
    // NTSTATUS ntsatCreateTokenResult = NtCreateToken(&hNewTokenHandle,
    //         TOKEN_ALL_ACCESS,
    //         NULL,
    //         TokenPrimary,
    //         &lAuthID,
    //         &liExpire,
    //         ptuTokenUser,
    //         ptgTokenGroups,
    //         ptpTokenPriviliges,
    //         NULL,
    //         ptgTokemPrimaryGroups,
    //         NULL,
    //         ptsTokenSource);

    // //Макрос NT_SUCCESS проверяет значение NTSTATUS ntsatCreateTokenResult на то, является ли оно положительным.
    //  if (NT_SUCCESS(ntsatCreateTokenResult)){
    //     wcout << ok << "Token recreated, checking it privileges..." << trail;
    //     printAllPrivileges(hNewTokenHandle);
    // }
    // else{
    //     wcout << err << "Something went wrong, NT_STATUS code: 0x" << hex << ntsatCreateTokenResult << trail;
    // }
    
    
    // wcout << "0x"<< hex << stat;

    TOKEN_USER tuNewTokenUser = TOKEN_USER();

    SID_AND_ATTRIBUTES ntuSid;
    ConvertStringSidToSidW(L"S-1-5-21-2345928754-353504623-3881109545-1000",&ntuSid.Sid);
    tuNewTokenUser.User = ntuSid;

    TOKEN_GROUPS tgNewTokenGroups = TOKEN_GROUPS();
    

}