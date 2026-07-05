#define UNICODE
#include <windows.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <string>
#include "resource.h"

#pragma comment(lib, "UxTheme.lib")
#pragma comment(lib, "Dwmapi.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

namespace CustomMessageMetrics {
    static const int BASE_DPI = 96;
    static const int FONT_POINT = 9;

    static const int MARGIN_DP = 12;
    static const int GAP_DP = 12;
    static const int BOTTOM_MARGIN_DP = 12;

    static const int BUTTON_WIDTH_DP = 80;
    static const int BUTTON_HEIGHT_DP = 26;

    static const int INITIAL_WIDTH_DP = 300;
    static const int INITIAL_HEIGHT_DP = 120;

    static const int MIN_TEXT_WIDTH_DP = 240;
    static const int MAX_TEXT_WIDTH_DP = 700;
    static const int WORKAREA_SIDE_MARGIN_DP = 80;

    static const COLORREF LIGHT_TEXT_COLOR = RGB(0, 0, 0);
    static const COLORREF DARK_TEXT_COLOR = RGB(240, 240, 240);
    static const COLORREF LIGHT_BACKGROUND_COLOR = RGB(255, 255, 255);
    static const COLORREF DARK_BACKGROUND_COLOR = RGB(32, 32, 32);
}

static int ScaleByDPI(int value, UINT dpi) {
    return MulDiv(value, dpi, CustomMessageMetrics::BASE_DPI);
}

typedef UINT (WINAPI *PFN_GetDpiForWindow)(HWND);
typedef UINT (WINAPI *PFN_GetDpiForSystem)(void);
typedef BOOL (WINAPI *PFN_AdjustWindowRectExForDpi)(LPRECT, DWORD, BOOL, DWORD, UINT);
typedef UINT (WINAPI *PFN_GetDpiForMonitor)(HMONITOR, int, UINT*, UINT*);

static UINT GetSystemDpiCompat() {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    PFN_GetDpiForSystem pGetDpiForSystem =
        user32 ? (PFN_GetDpiForSystem)GetProcAddress(user32, "GetDpiForSystem") : nullptr;
    if (pGetDpiForSystem) {
        return pGetDpiForSystem();
    }

    HDC hdc = GetDC(nullptr);
    UINT dpi = hdc ? (UINT)GetDeviceCaps(hdc, LOGPIXELSX) : 96;
    if (hdc) ReleaseDC(nullptr, hdc);
    return dpi ? dpi : CustomMessageMetrics::BASE_DPI;
}

static UINT GetWindowDpiCompat(HWND hwnd) {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    PFN_GetDpiForWindow pGetDpiForWindow =
        user32 ? (PFN_GetDpiForWindow)GetProcAddress(user32, "GetDpiForWindow") : nullptr;
    if (pGetDpiForWindow && hwnd) {
        return pGetDpiForWindow(hwnd);
    }
    return GetSystemDpiCompat();
}

static UINT GetMonitorDpiCompat(HMONITOR mon) {
    HMODULE shcore = LoadLibraryW(L"Shcore.dll");
    if (shcore) {
        PFN_GetDpiForMonitor pGetDpiForMonitor =
            (PFN_GetDpiForMonitor)GetProcAddress(shcore, "GetDpiForMonitor");
        if (pGetDpiForMonitor) {
            UINT x = CustomMessageMetrics::BASE_DPI, y = CustomMessageMetrics::BASE_DPI;
            if (SUCCEEDED(pGetDpiForMonitor(mon, 0 /* MDT_EFFECTIVE_DPI */, &x, &y))) {
                FreeLibrary(shcore);
                return x ? x : CustomMessageMetrics::BASE_DPI;
            }
        }
        FreeLibrary(shcore);
    }
    return GetSystemDpiCompat();
}

static BOOL AdjustWindowRectExForDpiCompat(LPRECT rc, DWORD style, BOOL menu, DWORD exStyle, UINT dpi) {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    PFN_AdjustWindowRectExForDpi pAdjustWindowRectExForDpi =
        user32 ? (PFN_AdjustWindowRectExForDpi)GetProcAddress(user32, "AdjustWindowRectExForDpi") : nullptr;
    if (pAdjustWindowRectExForDpi) {
        return pAdjustWindowRectExForDpi(rc, style, menu, exStyle, dpi);
    }
    return AdjustWindowRectEx(rc, style, menu, exStyle);
}

static bool IsDarkModeEnabled() {
    DWORD value = 1;
    DWORD size = sizeof(value);
    if (ERROR_SUCCESS == RegGetValueW(
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

struct CustomMsgState {
    HWND owner = nullptr;
    HWND hStatic = nullptr;
    HWND hButton = nullptr;
    HFONT hFont = nullptr;
    HBRUSH hbrBackground = nullptr;
    COLORREF textColor = RGB(0, 0, 0);
    LPCWSTR text = L"";
    LPCWSTR title = L"";
    UINT dpi = CustomMessageMetrics::BASE_DPI;
    bool done = false;
    int result = IDOK;
};

static void DeleteStateObjects(CustomMsgState* st) {
    if (!st) return;
    if (st->hFont) {
        DeleteObject(st->hFont);
        st->hFont = nullptr;
    }
    if (st->hbrBackground) {
        DeleteObject(st->hbrBackground);
        st->hbrBackground = nullptr;
    }
}

static HFONT CreateMessageFont(UINT dpi) {
    const int fontHeight = -MulDiv(CustomMessageMetrics::FONT_POINT, dpi, 72);
    return CreateFontW(fontHeight, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}

static RECT GetReferenceWorkArea(HWND hwnd, HWND owner) {
    HMONITOR mon = nullptr;
    if (owner && IsWindow(owner)) {
        mon = MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST);
    } else if (hwnd && IsWindow(hwnd)) {
        mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    } else {
        POINT pt;
        GetCursorPos(&pt);
        mon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
    }

    MONITORINFO mi = {};
    mi.cbSize = sizeof(mi);
    if (mon && GetMonitorInfoW(mon, &mi)) {
        return mi.rcWork;
    }

    RECT rc = {};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &rc, 0);
    return rc;
}

static int GetMaxTextWidth(HWND hwnd, HWND owner, UINT dpi) {
    RECT work = GetReferenceWorkArea(hwnd, owner);
    const int workW = work.right - work.left;

    int maxW = ScaleByDPI(CustomMessageMetrics::MAX_TEXT_WIDTH_DP, dpi);
    int limitW = workW - ScaleByDPI(CustomMessageMetrics::WORKAREA_SIDE_MARGIN_DP, dpi);
    if (limitW < ScaleByDPI(CustomMessageMetrics::MIN_TEXT_WIDTH_DP, dpi)) {
        limitW = ScaleByDPI(CustomMessageMetrics::MIN_TEXT_WIDTH_DP, dpi);
    }
    if (maxW > limitW) maxW = limitW;
    return maxW;
}

static RECT MeasureMessageText(HWND hwnd, HWND owner, HDC hdc, HFONT hFont, LPCWSTR text, UINT dpi) {
    HGDIOBJ oldFont = SelectObject(hdc, hFont);

    const int maxTextWidth = GetMaxTextWidth(hwnd, owner, dpi);

    RECT rcSingle = {0, 0, 0, 0};
    DrawTextW(hdc, text, -1, &rcSingle,
              DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);

    RECT rcText = {};
    if ((rcSingle.right - rcSingle.left) <= maxTextWidth && wcschr(text, L'\n') == nullptr) {
        rcText = rcSingle;
    } else {
        rcText = {0, 0, maxTextWidth, 0};
        DrawTextW(hdc, text, -1, &rcText,
                  DT_CALCRECT | DT_WORDBREAK | DT_EDITCONTROL | DT_NOPREFIX);
    }

    SelectObject(hdc, oldFont);
    return rcText;
}

static void ApplyDarkMode(HWND hwnd) {
    CustomMsgState* st = (CustomMsgState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (!st) return;

    const bool dark = IsDarkModeEnabled();
    const BOOL useDark = dark ? TRUE : FALSE;

    st->textColor = dark ? CustomMessageMetrics::DARK_TEXT_COLOR : CustomMessageMetrics::LIGHT_TEXT_COLOR;

    if (st->hbrBackground) {
        DeleteObject(st->hbrBackground);
        st->hbrBackground = nullptr;
    }
    st->hbrBackground = CreateSolidBrush(dark ? CustomMessageMetrics::DARK_BACKGROUND_COLOR : CustomMessageMetrics::LIGHT_BACKGROUND_COLOR);

    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDark, sizeof(useDark));

    if (st->hButton) {
        SetWindowTheme(st->hButton, dark ? L"DarkMode_Explorer" : L"Explorer", nullptr);
        SendMessageW(st->hButton, WM_THEMECHANGED, 0, 0);
    }

    InvalidateRect(hwnd, nullptr, TRUE);
}

static SIZE LayoutMessageWindow(HWND hwnd, CustomMsgState* st, UINT dpi, const RECT* suggestedWindowRect) {
    st->dpi = dpi;

    if (st->hFont) {
        DeleteObject(st->hFont);
        st->hFont = nullptr;
    }
    st->hFont = CreateMessageFont(dpi);

    const int margin = ScaleByDPI(CustomMessageMetrics::MARGIN_DP, dpi);
    const int gap = ScaleByDPI(CustomMessageMetrics::GAP_DP, dpi);
    const int bottomMargin = ScaleByDPI(CustomMessageMetrics::BOTTOM_MARGIN_DP, dpi);
    const int btnW = ScaleByDPI(CustomMessageMetrics::BUTTON_WIDTH_DP, dpi);
    const int btnH = ScaleByDPI(CustomMessageMetrics::BUTTON_HEIGHT_DP, dpi);

    HDC hdc = GetDC(hwnd);
    RECT rcText = MeasureMessageText(hwnd, st->owner, hdc, st->hFont, st->text, dpi);
    ReleaseDC(hwnd, hdc);

    const int measuredTextW = rcText.right - rcText.left;
    const int textW = max(measuredTextW, ScaleByDPI(CustomMessageMetrics::MIN_TEXT_WIDTH_DP, dpi));
    const int textH = rcText.bottom - rcText.top;
    const int clientW = max(textW + margin * 2, btnW + margin * 2);
    const int clientH = margin + textH + gap + btnH + bottomMargin;

    const DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
    const DWORD exStyle = 0;
    RECT wr = {0, 0, clientW, clientH};
    AdjustWindowRectExForDpiCompat(&wr, style, FALSE, exStyle, dpi);

    const int wndW = wr.right - wr.left;
    const int wndH = wr.bottom - wr.top;

    if (hwnd && IsWindow(hwnd)) {
        int x = 0;
        int y = 0;
        if (suggestedWindowRect) {
            x = suggestedWindowRect->left;
            y = suggestedWindowRect->top;
        } else {
            RECT ref = {};
            if (st->owner && IsWindow(st->owner)) {
                GetWindowRect(st->owner, &ref);
            } else {
                ref = GetReferenceWorkArea(hwnd, st->owner);
            }
            x = ref.left + ((ref.right - ref.left) - wndW) / 2;
            y = ref.top + ((ref.bottom - ref.top) - wndH) / 2;
        }

        SetWindowPos(hwnd, nullptr, x, y, wndW, wndH, SWP_NOZORDER | SWP_NOACTIVATE);

        if (st->hStatic) {
            SetWindowPos(st->hStatic, nullptr,
                         margin, margin,
                         textW, textH,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            SendMessageW(st->hStatic, WM_SETFONT, (WPARAM)st->hFont, TRUE);
        }

        if (st->hButton) {
            SetWindowPos(st->hButton, nullptr,
                         (clientW - btnW) / 2,
                         margin + textH + gap,
                         btnW, btnH,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            SendMessageW(st->hButton, WM_SETFONT, (WPARAM)st->hFont, TRUE);
        }
    }

    SIZE sz = {wndW, wndH};
    return sz;
}

/** @brief Ctrl-C custom message */
static void CopyMessageBoxTextToClipboard(HWND hwnd, const CustomMsgState* st) {
    if (!st) return;

    std::wstring s;
    s += L"---------------------------\r\n";
    s += st->title ? st->title : L"";
    s += L"\r\n---------------------------\r\n";
    s += st->text ? st->text : L"";
    s += L"\r\n---------------------------\r\n";
    s += L"OK\r\n";
    s += L"---------------------------\r\n";

    const SIZE_T bytes = (s.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hMem) return;

    void* p = GlobalLock(hMem);
    if (!p) {
        GlobalFree(hMem);
        return;
    }

    memcpy(p, s.c_str(), bytes);
    GlobalUnlock(hMem);

    if (!OpenClipboard(hwnd)) {
        GlobalFree(hMem);
        return;
    }

    EmptyClipboard();
    SetClipboardData(CF_UNICODETEXT, hMem);
    CloseClipboard();
}

static LRESULT CALLBACK MsgWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    CustomMsgState* st = (CustomMsgState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    switch (msg) {
    case WM_NCCREATE: {
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)cs->lpCreateParams);
        return TRUE;
    }

    case WM_CREATE: {
        st = (CustomMsgState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        if (!st) return -1;

        SetWindowTextW(hwnd, st->title ? st->title : L"");

        st->hStatic = CreateWindowExW(
            0, L"STATIC", st->text,
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 0, 0,
            hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);

        st->hButton = CreateWindowExW(
            0, L"BUTTON", L"OK",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
            0, 0, 0, 0,
            hwnd, (HMENU)IDOK, GetModuleHandleW(nullptr), nullptr);

        LayoutMessageWindow(hwnd, st, st->dpi, nullptr);
        ApplyDarkMode(hwnd);
        SetFocus(st->hButton);
        return 0;
    }

    case WM_DPICHANGED: {
        if (st) {
            UINT dpi = HIWORD(wParam);
            RECT* suggested = (RECT*)lParam;
            LayoutMessageWindow(hwnd, st, dpi, suggested);
            ApplyDarkMode(hwnd);
        }
        return 0;
    }

    case WM_SETTINGCHANGE:
        if (lParam && lstrcmpW((LPCWSTR)lParam, L"ImmersiveColorSet") == 0) {
            ApplyDarkMode(hwnd);
        }
        return 0;

    case WM_THEMECHANGED:
        ApplyDarkMode(hwnd);
        return 0;

    case WM_ERASEBKGND: {
        if (!st || !st->hbrBackground) break;
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, st->hbrBackground);
        return 1;
    }

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        if (!st || !st->hbrBackground) break;
        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, st->textColor);
        return (LRESULT)st->hbrBackground;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_COPY_MESSAGE) {
            CopyMessageBoxTextToClipboard(hwnd, st);
            return 0;
        }
        if (LOWORD(wParam) == IDOK) {
            if (st) {
                st->result = IDOK;
                st->done = true;
            }
            DestroyWindow(hwnd);
            return 0;
        }
        break;

    case WM_CLOSE:
        if (st) {
            st->result = IDCANCEL;
            st->done = true;
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_NCDESTROY:
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        break;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int ShowCustomMessage(HWND owner, LPCWSTR text, LPCWSTR title) {
    if (!text) text = L"";
    if (!title) title = L"";

    static ATOM s_atom = 0;
    HINSTANCE hInst = GetModuleHandleW(nullptr);

    if (!s_atom) {
        WNDCLASSEXW wcx = {};
        wcx.cbSize = sizeof(WNDCLASSEXW);
        wcx.style = CS_HREDRAW | CS_VREDRAW;
        wcx.lpfnWndProc = MsgWndProc;
        wcx.hInstance = hInst;
        wcx.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wcx.hbrBackground = nullptr;
        wcx.lpszClassName = L"CustomMsgDlg";
        wcx.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(IDR_MSGBOX));
        wcx.hIconSm = LoadIconW(hInst, MAKEINTRESOURCEW(IDR_MSGBOX));
        s_atom = RegisterClassExW(&wcx);
        if (!s_atom) {
            return 0;
        }
    }

    CustomMsgState st;
    st.owner = owner;
    st.text = text;
    st.title = title;

    if (owner && IsWindow(owner)) {
        st.dpi = GetWindowDpiCompat(owner);
    } else {
        POINT pt;
        GetCursorPos(&pt);
        HMONITOR mon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
        st.dpi = GetMonitorDpiCompat(mon);
    }

    const DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;

    HWND hwnd = CreateWindowExW(
        0, L"CustomMsgDlg", title,
        style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        ScaleByDPI(CustomMessageMetrics::INITIAL_WIDTH_DP, st.dpi), ScaleByDPI(CustomMessageMetrics::INITIAL_HEIGHT_DP, st.dpi),
        owner, nullptr, hInst,
        &st);

    if (!hwnd) {
        DeleteStateObjects(&st);
        return 0;
    }

    ACCEL acc[] = {
        {FVIRTKEY, VK_RETURN, IDOK},
        {FVIRTKEY, VK_ESCAPE, IDOK},
        {FVIRTKEY | FCONTROL, 'C', IDC_COPY_MESSAGE},
    };
    HACCEL hAcc = CreateAcceleratorTableW(acc, ARRAYSIZE(acc));

    if (owner && IsWindow(owner)) {
        EnableWindow(owner, FALSE);
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (!st.done && GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (hAcc && TranslateAcceleratorW(hwnd, hAcc, &msg)) {
            continue;
        }
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if (owner && IsWindow(owner)) {
        EnableWindow(owner, TRUE);
        SetActiveWindow(owner);
    }

    if (hAcc) {
        DestroyAcceleratorTable(hAcc);
    }

    DeleteStateObjects(&st);
    return st.result;
}
