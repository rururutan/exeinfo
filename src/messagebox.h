#pragma once
#include <windows.h>

/**
 * @brief Display a message dialog.
 * @param owner Owner Window
 * @param text Text to display. nullptr is treated as an empty string.
 * @param title String to display in the title bar. `nullptr` is treated as an empty string.
 * @retval IDOK
 * @retval IDCANCEL
 * @retval 0 if creation fails
 */
int ShowCustomMessage(HWND owner, LPCWSTR text, LPCWSTR title);
