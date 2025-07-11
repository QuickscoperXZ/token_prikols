#include <iostream>
#include <Windows.h>
#include <sddl.h> //необходимо для конвертации SID-a

  
int main(int argc, char *argv[]){
 int iPid = GetCurrentProcessId(); // получение SID-а текущего процесса
 std::cout << "[+] Got current process:" << iPid << '\n';
 
 HANDLE hCurrentProcess = OpenProcess(PROCESS_ALL_ACCESS,0,iPid); //открытие процесса по PID-у
 
 HANDLE hTokenHandle = NULL; //инициализация хэндла 
 
 OpenProcessToken(hCurrentProcess,TOKEN_READ,&hTokenHandle); //получение хэндла токена, параметры: хэндл на процесс, предпочитаемый доступ и указатель на хэндл токена
 std::cout << "[+] Got Process token handle" << '\n';
 
 u_long uTokenLength = 0; // инициализация длинны токена
 GetTokenInformation(hTokenHandle,TokenUser, 0, NULL,&uTokenLength); //получение информации - структуры SID_AND_ATTRIBUTES из дескриптора безопасности токена, параметры: хэндл на токен, запрашиваемая информация, указатель на объект TOKEN_USER, размер объекта в памяти, указатель на размер объекта
 
 TOKEN_USER tokenInfo = TOKEN_USER(); //инициализация структуры TOKEN_USER
 GetTokenInformation(hTokenHandle,TokenUser, &tokenInfo, uTokenLength, &uTokenLength);//запрос данных о токене
 std::cout << "[+] Token Length: " << uTokenLength << '\n';
 
 LPSTR sidString =nullptr; //инициализация строки вывода
 ConvertSidToStringSidA((&tokenInfo)->User.Sid,&sidString); //конвертация структуры TOKEN_USER.SID_AND_ATTRIBUTES.SID в строку
 
 std::wcout << sidString; //вывод информации

}