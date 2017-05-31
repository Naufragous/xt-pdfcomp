/*
    PDF Compatibility viewer X-Tension for X-Ways Forensics
    Copyright (C) 2017 R. Yushaev

    This program uses the Ghostscript library
    Copyright (C) 2001-2019 Artifex Software, Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <windows.h>

// Ghostscript does not promise backward API compatibility
// Require the exact same version that was used during development
#define REQUIRED_GS_REVISION 926 // 9.26

#define EXPORT __declspec (dllexport)

HANDLE heap = NULL;

// X-Tension API
// https://www.x-ways.net/forensics/x-tensions/api.html

#define XTAPI  __stdcall

#define XT_INIT_XWF        0x00000001
#define XT_INIT_WHX        0x00000002
#define XT_INIT_XWI        0x00000004
#define XT_INIT_BETA       0x00000008
#define XT_INIT_QUICKCHECK 0x00000020
#define XT_INIT_ABOUTONLY  0x00000040

typedef INT64 (XTAPI *fptr_XWF_GetSize)       (HANDLE, LPVOID);
typedef void  (XTAPI *fptr_XWF_OutputMessage) (LPWSTR, DWORD);
typedef DWORD (XTAPI *fptr_XWF_Read)          (HANDLE, INT64, LPVOID, DWORD);

fptr_XWF_GetSize       XWF_GetSize       = NULL;
fptr_XWF_OutputMessage XWF_OutputMessage = NULL;
fptr_XWF_Read          XWF_Read          = NULL;

// GhostScript API
// https://www.ghostscript.com/doc/9.26/API.htm

typedef struct gsapi_revision_s
{
    const char *product;
    const char *copyright;
    long revision;
    long revisiondate;
} gsapi_revision_t;

void gsapi_delete_instance (void *instance);
int  gsapi_exit            (void *instance);
int  gsapi_init_with_args  (void *instance, int argc, char **argv);
int  gsapi_new_instance    (void **pinstance, void *caller_handle);
int  gsapi_revision        (gsapi_revision_t *pr, int len);

BOOL WINAPI
DllMain (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    // Check the version only during the initial call
    if (DLL_PROCESS_ATTACH == fdwReason)
    {
        gsapi_revision_t rev;

        if (0 == gsapi_revision (&rev, sizeof (rev)) &&
            REQUIRED_GS_REVISION == rev.revision)
        {
            return TRUE;
        }
        else
        {
            MessageBoxW (NULL, L"Wrong Ghostscript version.", L"Error", MB_ICONERROR);
            
            return FALSE;
        }
    }
    else
    {
        // DLL_PROCESS_DETACH
        // DLL_THREAD_ATTACH
        // DLL_THREAD_DETACH
        return TRUE;
    }
}

EXPORT LONG XTAPI
XT_About (HANDLE hParentWnd, PVOID lpReserved)
{
    LPCWSTR about = L"PDF Compatibility X-Tension\n\n"
                     "This viewer X-Tension attempts to fix the issue with the\n"
                     "missing fonts that occurs when printing PDF documents.\n\n"
                     "It uses the Ghostscript library to internally preprocess\n"
                     "the PDF files before passing them on to the built-in PDF\n"
                     "viewer component of X-Ways Forensics.\n\n"
                     "Source code available at:\n"
                     "https://github.com/Naufragous/xt-pdfcomp\n\n"
                     "Author: R. Yushaev";
    MessageBoxW (NULL, about, L"About", MB_ICONINFORMATION);

    return 0;
}

EXPORT LONG XTAPI
XT_Done (PVOID lpReserved)
{
    return 0;
}

EXPORT LONG XTAPI
XT_Init (DWORD nVersion, DWORD nFlags, HANDLE hMainWnd, void* LicInfo)
{
    // WinHex does not support viewer X-Tensions
    if (XT_INIT_WHX & nFlags) return -1;

    // Do not need to load anything for those calls
    if (XT_INIT_ABOUTONLY  & nFlags) return 2;
    if (XT_INIT_QUICKCHECK & nFlags) return 2;

    heap = GetProcessHeap ();
    if (!heap) return -1;

    HMODULE h = GetModuleHandleW (NULL);
    if (h)
    {
        XWF_GetSize       = (fptr_XWF_GetSize)       GetProcAddress (h, "XWF_GetSize");
        XWF_OutputMessage = (fptr_XWF_OutputMessage) GetProcAddress (h, "XWF_OutputMessage");
        XWF_Read          = (fptr_XWF_Read)          GetProcAddress (h, "XWF_Read");
    }

    if (NULL == XWF_GetSize ||
        NULL == XWF_OutputMessage ||
        NULL == XWF_Read)
    {
        return -1;
    }

    XWF_OutputMessage (L"PDF Compatibility viewer X-Tension loaded.", 2);

    return 2;
}

EXPORT BOOL XTAPI
XT_ReleaseMem (PVOID lpBuffer)
{
    if (lpBuffer && 0 == HeapFree (heap, 0, lpBuffer))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

EXPORT PVOID XTAPI
XT_View (HANDLE hItem, LONG nItemID, HANDLE hVolume, HANDLE hEvidence, PVOID lpReserved, PINT64 nResSize)
{
    // Fallback status: "Not responsible for this type of file"
    *nResSize = -1;

    const INT64 file_size = XWF_GetSize (hItem, (LPVOID) 1);
    if (150 > file_size)
    {
        // Too small to be a valid PDF file
        return NULL;
    }

    char signature_buf[5] = { 0 };
    const DWORD sig_bytes_read = XWF_Read (hItem, 0, signature_buf, 4);
    if (4 != sig_bytes_read || 0 != strcmp ("%PDF", signature_buf))
    {
        return NULL;
    }

    // From here on default status will be "an error occured"
    *nResSize = -2;

    char *file_buf = (char*) HeapAlloc (heap, 0, file_size);
    if (!file_buf)
    {
        return NULL;
    }

    if (file_size != XWF_Read (hItem, 0, file_buf, (DWORD) file_size))
    {
        HeapFree (heap, 0, file_buf);

        return NULL;
    }

    // We will interact with the Ghostscript library using two
    // temporary files provided by the WinAPI.
    wchar_t tmp_path[MAX_PATH];
    wchar_t tmp_src_filename[MAX_PATH];
    wchar_t tmp_dst_filename[MAX_PATH];

    if (0 == GetTempPathW (MAX_PATH, tmp_path) ||
        0 == GetTempFileNameW (tmp_path, L"PCX", 0, tmp_src_filename) ||
        0 == GetTempFileNameW (tmp_path, L"PCX", 0, tmp_dst_filename))
    {
        HeapFree (heap, 0, file_buf);

        return NULL;
    }

    HANDLE tmp_src_file = CreateFileW (
        tmp_src_filename,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_TEMPORARY,
        NULL
    );
    if (INVALID_HANDLE_VALUE == tmp_src_file)
    {
        HeapFree (heap, 0, file_buf);

        DeleteFileW (tmp_src_filename);
        DeleteFileW (tmp_dst_filename);

        return NULL;
    }

    DWORD bytes_written = 0;
    if (FALSE == WriteFile (tmp_src_file, file_buf, (DWORD) file_size, &bytes_written, NULL) ||
        file_size != bytes_written)
    {
        HeapFree (heap, 0, file_buf);

        CloseHandle (tmp_src_file);
        DeleteFileW  (tmp_src_filename);
        DeleteFileW  (tmp_dst_filename);

        return NULL;
    }

    HeapFree (heap, 0, file_buf);

    CloseHandle (tmp_src_file);

    int gs_errors = 0;

    void *pinstance     = NULL;
    void *caller_handle = NULL;

    if (0 == gsapi_new_instance (&pinstance, caller_handle))
    {
        // Although it should be possible to pass WCHAR* using
        // gsapi_set_arg_encoding(), it is prone to fatal errors
        // and segmentation faults.
        const int src_mb_size = WideCharToMultiByte (CP_UTF8, 0, tmp_src_filename, -1, NULL, 0, NULL, NULL);
        const int dst_mb_size = WideCharToMultiByte (CP_UTF8, 0, tmp_dst_filename, -1, NULL, 0, NULL, NULL);

        char *tmp_src_filename_mb = (char*) HeapAlloc (heap, 0, src_mb_size);
        char *tmp_dst_filename_mb = (char*) HeapAlloc (heap, 0, dst_mb_size);

        WideCharToMultiByte (CP_UTF8, 0, tmp_src_filename, -1, tmp_src_filename_mb, src_mb_size, NULL, NULL);
        WideCharToMultiByte (CP_UTF8, 0, tmp_dst_filename, -1, tmp_dst_filename_mb, dst_mb_size, NULL, NULL);

        // GhostScript parameters
        char *argv[10];

        argv[0] = "1337";                     // first element is ignored
        argv[1] = "-sDEVICE=pdfwrite";        // creates a PDF file
        argv[2] = "-dNoOutputFonts";          // IMPORTANT: fixes font bug
        argv[3] = "-dCompatibilityLevel=1.5"; // PDF version of the output file
        argv[4] = "-r300";                    // DPI resolution
        argv[5] = "-dQUIET";                  // disable comments on stdout
        argv[6] = "-dSAFER";                  // restrict file operations
        argv[7] = "-o";                       // includes -dBATCH and -dNOPAUSE
        argv[8] = tmp_dst_filename_mb;
        argv[9] = tmp_src_filename_mb;

        if (0 != gsapi_init_with_args (pinstance, 10, argv))
        {
            gs_errors++;
        }

        HeapFree (heap, 0, tmp_src_filename_mb);
        HeapFree (heap, 0, tmp_dst_filename_mb);
    }
    else
    {
        gs_errors++;
    }

    DeleteFileW (tmp_src_filename);

    if (0 != gsapi_exit (pinstance))
    {
        gs_errors++;
    }

    gsapi_delete_instance (pinstance);

    if (gs_errors)
    {
        XWF_OutputMessage (L"[ERROR] GhostScript conversion failed.", 2);

        DeleteFileW (tmp_dst_filename);

        return NULL;
    }

    HANDLE tmp_dst_file = CreateFileW (
        tmp_dst_filename,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_TEMPORARY,
        NULL
    );
    if (INVALID_HANDLE_VALUE == tmp_dst_file)
    {
        DeleteFileW (tmp_dst_filename);

        return NULL;
    }

    const DWORD tmp_dst_filesize = GetFileSize (tmp_dst_file, NULL);

    file_buf = (char*) HeapAlloc (heap, 0, tmp_dst_filesize);
    if (!file_buf)
    {
        DeleteFileW (tmp_dst_filename);

        return NULL;
    }

    DWORD bytes_read = 0;
    if (FALSE == ReadFile (tmp_dst_file, file_buf, tmp_dst_filesize, &bytes_read, NULL) ||
        tmp_dst_filesize != bytes_read)
    {
        HeapFree (heap, 0, file_buf);

        CloseHandle (tmp_dst_file);
        DeleteFileW  (tmp_dst_filename);

        return NULL;
    }

    CloseHandle (tmp_dst_file);
    DeleteFileW  (tmp_dst_filename);

    *nResSize = bytes_read;

    return file_buf;
}
