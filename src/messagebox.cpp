#define UNICODE
#include <windows.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include "resource.h"
#pragma comment(lib, "UxTheme.lib")
#pragma comment(lib, "Dwmapi.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")

static HBRUSH g_hbrBackground = NULL;
static COLORREF g_textColor = RGB(0, 0, 0);

static int ScaleByDPI(int value, UINT dpi) {
    return MulDiv(value, dpi, 96);
}

static bool IsDarkModeEnabled() {
    DWORD value = 1;
    DWORD size = sizeof(value);
    if (ERROR_SUCCESS == RegGetValue(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            L"AppsUseLightTheme",
            RRF_RT_REG_DWORD,
            nullptr,
            &value,
            &size)) {
        return value == 0;
    }
    return false;
}

void ApplyDarkMode(HWND hwnd) {
    bool dark = IsDarkModeEnabled();
    BOOL useDark = dark;
    g_textColor = dark ? RGB(240,240,240) : RGB(0,0,0);
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDark, sizeof(useDark));
    if (g_hbrBackground) DeleteObject(g_hbrBackground);
    g_hbrBackground = CreateSolidBrush(dark ? RGB(32,32,32) : RGB(255,255,255));
    HWND hBtn = GetDlgItem(hwnd, IDOK);
    if (hBtn) {
        SetWindowTheme(hBtn, dark ? L"DarkMode_Explorer" : L"Explorer", NULL);
        SendMessageW(hBtn, WM_THEMECHANGED, 0, 0);
    }
    InvalidateRect(hwnd, NULL, TRUE);
    UpdateWindow(hwnd);
}

LRESULT CALLBACK MsgWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        ApplyDarkMode(hwnd);
        break;
    case WM_DPICHANGED: {
        RECT* prcNew = (RECT*)lParam;
        SetWindowPos(hwnd, NULL,
            prcNew->left, prcNew->top,
            prcNew->right - prcNew->left,
            prcNew->bottom - prcNew->top,
            SWP_NOZORDER | SWP_NOACTIVATE);
        ApplyDarkMode(hwnd);
        InvalidateRect(hwnd, NULL, TRUE);
        break;
    }
    case WM_SETTINGCHANGE:
        if (lParam && lstrcmp((LPCWSTR)lParam, L"ImmersiveColorSet") == 0)
            ApplyDarkMode(hwnd);
        break;
    case WM_THEMECHANGED:
        ApplyDarkMode(hwnd);
        break;
    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_hbrBackground);
        return 1;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, g_textColor);
        return (INT_PTR)g_hbrBackground;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK)
            DestroyWindow(hwnd);
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        if (g_hbrBackground) DeleteObject(g_hbrBackground);
        PostQuitMessage(0);
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int ShowCustomMessage(HWND owner, LPCWSTR text, LPCWSTR title) {
    UINT dpi = GetDpiForSystem();

    const int maxTextWidth = ScaleByDPI(400, dpi);
    const int margin = ScaleByDPI(10, dpi), gap = ScaleByDPI(10, dpi), bottomMargin = ScaleByDPI(10, dpi);
    const int btnW = ScaleByDPI(80, dpi), btnH = ScaleByDPI(25, dpi);

    int fontHeight = -MulDiv(9, dpi, 72);
    HFONT hFont = CreateFontW(fontHeight, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    HDC hdcMem = CreateCompatibleDC(NULL);
    SelectObject(hdcMem, hFont);
    RECT rcText = {0, 0, maxTextWidth, 0};
    DrawTextW(hdcMem, text, -1, &rcText,
              DT_CALCRECT | DT_WORDBREAK | DT_EDITCONTROL);
    DeleteDC(hdcMem);

    int totalW = rcText.right + margin * 2;
    int totalH = margin + rcText.bottom + gap + btnH + bottomMargin;

    WNDCLASSEXW wcx = {};
    wcx.cbSize = sizeof(WNDCLASSEXW);
    wcx.style = CS_HREDRAW | CS_VREDRAW;
    wcx.lpfnWndProc = MsgWndProc;
    wcx.hInstance = GetModuleHandle(NULL);
    wcx.lpszClassName = L"CustomMsgDlg";
    wcx.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDR_MSGBOX));
    wcx.hIconSm = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDR_MSGBOX));
    RegisterClassExW(&wcx);

    RECT wr = {0, 0, totalW, totalH};
    AdjustWindowRectEx(&wr,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        FALSE, 0);
    int wndW = wr.right - wr.left;
    int wndH = wr.bottom - wr.top;

    RECT rcOwner;
    if (owner && IsWindow(owner)) {
        GetWindowRect(owner, &rcOwner);
    }
    else {
        SystemParametersInfo(SPI_GETWORKAREA, 0, &rcOwner, 0);
    }
    int x = rcOwner.left + ((rcOwner.right - rcOwner.left) - wndW) / 2;
    int y = rcOwner.top + ((rcOwner.bottom - rcOwner.top) - wndH) / 2;

    HWND hwnd = CreateWindowExW(
        0, wcx.lpszClassName, title,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        x, y,
        wndW, wndH,
        owner, NULL, wcx.hInstance,
        (LPVOID)NULL);

    HWND hStatic = CreateWindowExW(
        0, L"STATIC", text,
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
        margin, margin,
        rcText.right, rcText.bottom,
        hwnd, NULL, wcx.hInstance, NULL);
    SendMessageW(hStatic, WM_SETFONT,
                 (WPARAM)hFont, TRUE);

    HWND hBtn = CreateWindowExW(
        0, L"BUTTON", L"OK",
        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
        (totalW - btnW) / 2,
        margin + rcText.bottom + gap,
        btnW, btnH,
        hwnd, (HMENU)IDOK, wcx.hInstance, NULL);
    SendMessageW(hBtn, WM_SETFONT,
                 (WPARAM)hFont, TRUE);
    SetFocus(hBtn);

    ApplyDarkMode(hwnd);

    ACCEL acc[] = {{FVIRTKEY, VK_RETURN, IDOK}, {FVIRTKEY, VK_ESCAPE, IDOK}};
    HACCEL hAcc = CreateAcceleratorTableW(acc, ARRAYSIZE(acc));

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!TranslateAcceleratorW(hwnd, hAcc, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    DestroyAcceleratorTable(hAcc);
    DeleteObject(hFont);
    return (int)msg.wParam;
}
