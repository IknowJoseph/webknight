#include "stdafx.h"
#include "SandboxFile.h"

//Source: MFC filecore.cpp

// This is a part of the Microsoft Foundation Classes C++ library.
// Copyright (C) Microsoft Corporation
// All rights reserved.
//
// This source code is only intended as a supplement to the
// Microsoft Foundation Classes Reference and related
// electronic documentation provided with the library.
// See these sources for detailed information regarding the
// Microsoft Foundation Classes product.

#include <winnetwk.h>
#include <shlobj.h>
#include <shellapi.h>
#include <Strsafe.h>
#if _MSC_VER >= 1400 // VS 8.0
#include "sal.h"
#endif

CSandboxFile::CSandboxFile(void)
{
}

CSandboxFile::CSandboxFile(HANDLE hFile):CFile(
#if _MSC_VER < 1300 // <= VS 6.0
(int)
#endif
	hFile)
{
}

CSandboxFile::CSandboxFile(LPCTSTR lpszFileName, UINT nOpenFlags):CFile(lpszFileName,nOpenFlags)
{
}

CSandboxFile::~CSandboxFile(void)
{
}

#if _MSC_VER >= 1400 // VS 8.0
//same as filecore.cpp
BOOL CSandboxFile::Open(LPCTSTR lpszFileName, UINT nOpenFlags, CFileException* pException)
{
	ASSERT_VALID(this);
	ASSERT(AfxIsValidString(lpszFileName));

	ASSERT(pException == NULL ||
		AfxIsValidAddress(pException, sizeof(CFileException)));
	ASSERT((nOpenFlags & typeText) == 0);   // text mode not supported

	// shouldn't open an already open file (it will leak)
	ASSERT(m_hFile == INVALID_HANDLE_VALUE);

	// CFile objects are always binary and CreateFile does not need flag
	nOpenFlags &= ~(UINT)typeBinary;

	m_bCloseOnDelete = FALSE;

	m_hFile = INVALID_HANDLE_VALUE;
	m_strFileName.Empty();

	TCHAR szTemp[_MAX_PATH];
	if (lpszFileName != NULL && SUCCEEDED(StringCchLength(lpszFileName, _MAX_PATH, NULL)) )
	{
		if( _AfxFullPath2(szTemp, lpszFileName,pException) == FALSE )
			return FALSE;
	}
	else
	{
		// user passed in a buffer greater than _MAX_PATH
		if (pException != NULL)
		{
			pException->m_cause = CFileException::badPath;
			pException->m_strFileName = lpszFileName;
		}
		return FALSE; // path is too long
	}
		
	m_strFileName = szTemp;
	ASSERT(shareCompat == 0);

	// map read/write mode
	ASSERT((modeRead|modeWrite|modeReadWrite) == 3);
	DWORD dwAccess = 0;
	switch (nOpenFlags & 3)
	{
	case modeRead:
		dwAccess = GENERIC_READ;
		break;
	case modeWrite:
		dwAccess = GENERIC_WRITE;
		break;
	case modeReadWrite:
		dwAccess = GENERIC_READ | GENERIC_WRITE;
		break;
	default:
		ASSERT(FALSE);  // invalid share mode
	}

	// map share mode
	DWORD dwShareMode = 0;
	switch (nOpenFlags & 0x70)    // map compatibility mode to exclusive
	{
	default:
		ASSERT(FALSE);  // invalid share mode?
	case shareCompat:
	case shareExclusive:
		dwShareMode = 0;
		break;
	case shareDenyWrite:
		dwShareMode = FILE_SHARE_READ;
		break;
	case shareDenyRead:
		dwShareMode = FILE_SHARE_WRITE;
		break;
	case shareDenyNone:
		dwShareMode = FILE_SHARE_WRITE | FILE_SHARE_READ;
		break;
	}

	// Note: typeText and typeBinary are used in derived classes only.

	// map modeNoInherit flag
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = (nOpenFlags & modeNoInherit) == 0;

	// map creation flags
	DWORD dwCreateFlag;
	if (nOpenFlags & modeCreate)
	{
		if (nOpenFlags & modeNoTruncate)
			dwCreateFlag = OPEN_ALWAYS;
		else
			dwCreateFlag = CREATE_ALWAYS;
	}
	else
		dwCreateFlag = OPEN_EXISTING;

	// special system-level access flags

	// Random access and sequential scan should be mutually exclusive
	ASSERT((nOpenFlags&(osRandomAccess|osSequentialScan)) != (osRandomAccess|
		osSequentialScan) );

	DWORD dwFlags = FILE_ATTRIBUTE_NORMAL;
	if (nOpenFlags & osNoBuffer)
		dwFlags |= FILE_FLAG_NO_BUFFERING;
	if (nOpenFlags & osWriteThrough)
		dwFlags |= FILE_FLAG_WRITE_THROUGH;
	if (nOpenFlags & osRandomAccess)
		dwFlags |= FILE_FLAG_RANDOM_ACCESS;
	if (nOpenFlags & osSequentialScan)
		dwFlags |= FILE_FLAG_SEQUENTIAL_SCAN;

	// attempt file creation
	HANDLE hFile = ::CreateFile(lpszFileName, dwAccess, dwShareMode, &sa,
		dwCreateFlag, dwFlags, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		_AfxFillExceptionInfo(pException,lpszFileName);		
		return FALSE;
	}
	m_hFile = hFile;
	m_bCloseOnDelete = TRUE;

	return TRUE;
}

//same as filecore.cpp
void CSandboxFile::_AfxFillExceptionInfo(CFileException* pException,LPCTSTR lpszFileName)
{
	if (pException != NULL)
	{
		pException->m_lOsError = ::GetLastError();
		pException->m_cause =
			CFileException::OsErrorToException(pException->m_lOsError);

		// use passed file name (not expanded vesion) when reporting
		// an error while opening

		pException->m_strFileName = lpszFileName;
	}
}

//this one is different from filecore.cpp
BOOL CSandboxFile::_AfxFullPath2(_Out_z_cap_c_(_MAX_PATH) LPTSTR lpszPathOut, LPCTSTR lpszFileIn, CFileException* pException)
	// lpszPathOut = buffer of _MAX_PATH
	// lpszFileIn = file, relative path or absolute path
	// (both in ANSI character set)
	// pException - pointer to exception object - can be NULL.
{
	pException;
	ENSURE(lpszPathOut);
	ENSURE(lpszFileIn);
	ASSERT(AfxIsValidAddress(lpszPathOut, _MAX_PATH));

	// first, fully qualify the path name
	LPTSTR lpszFilePart;
	DWORD dwRet = GetFullPathName(lpszFileIn, _MAX_PATH, lpszPathOut, &lpszFilePart);
	if (dwRet == 0)
	{
#ifdef _DEBUG
		if (lpszFileIn != NULL && lpszFileIn[0] != '\0')
			TRACE(traceAppMsg, 0, _T("Warning: could not parse the path '%s'.\n"), lpszFileIn);
#endif
		Checked::tcsncpy_s(lpszPathOut, _MAX_PATH, lpszFileIn, _TRUNCATE); // take it literally
		_AfxFillExceptionInfo(pException,lpszFileIn);
		return FALSE;
	}
	else if (dwRet >= _MAX_PATH)
	{
		#ifdef _DEBUG
			if (lpszFileIn[0] != '\0')
				TRACE1("Warning: could not parse the path '%s'. Path is too long.\n", lpszFileIn);
		#endif
		// GetFullPathName() returned a path greater than _MAX_PATH
		if (pException != NULL)
		{
			pException->m_cause = CFileException::badPath;
			pException->m_strFileName = lpszFileIn;
		}
		return FALSE; // long path won't fit in buffer
	}

	/*
	 * Symptom: WebKnight using default settings even if permissions on WebKnight folder are correct
	 * WebKnight 2.1 did not have this issue -> compiled in VS 6.0
	 *
	 * The CFile code generates an error in sandbox mode (no QueryVolumeInformation permissions on C:\)
	 * FIX: We just handle all paths as if it were UNC paths (no filesystem checks)
	 * The VS6 version of filecore.cpp did not have this issue as well, because it simply
	 * ignored errors generated by AfxFullPath.
	 *
	 * The issue is also described here:
	 * https://connect.microsoft.com/VisualStudio/feedback/details/800932/cfile-mfc-does-not-work-with-internet-explorer-enhanced-protected-mode-cfile-open-fails
	 *
	 */

	//CString strRoot;
	//// determine the root name of the volume
	//AfxGetRoot(lpszPathOut, strRoot);

	//if (!::PathIsUNC( strRoot ))
	//{
	//	// get file system information for the volume
	//	DWORD dwFlags, dwDummy;
	//	if (!GetVolumeInformation(strRoot, NULL, 0, NULL, &dwDummy, &dwFlags,
	//		NULL, 0))
	//	{
	//		TRACE(traceAppMsg, 0, _T("Warning: could not get volume information '%s'.\n"),
	//			(LPCTSTR)strRoot);
	//		_AfxFillExceptionInfo(pException,lpszFileIn);
	//		return FALSE;   // preserving case may not be correct
	//	}

	//	// not all characters have complete uppercase/lowercase
	//	if (!(dwFlags & FS_CASE_IS_PRESERVED))
	//		CharUpper(lpszPathOut);

	//	// assume non-UNICODE file systems, use OEM character set
	//	if (!(dwFlags & FS_UNICODE_STORED_ON_DISK))
	//	{
	//		WIN32_FIND_DATA data;
	//		HANDLE h = FindFirstFile(lpszFileIn, &data);
	//		if (h != INVALID_HANDLE_VALUE)
	//		{
	//			FindClose(h);
	//			if(lpszFilePart != NULL && lpszFilePart > lpszPathOut)
	//			{
	//				int nFileNameLen = lstrlen(data.cFileName);
	//				int nIndexOfPart = (int)(lpszFilePart - lpszPathOut);
	//				if ((nFileNameLen + nIndexOfPart) < _MAX_PATH)
	//				{
	//					Checked::tcscpy_s(lpszFilePart, _MAX_PATH - nIndexOfPart, data.cFileName);
	//				}
	//				else
	//				{
	//					// the path+filename of the file is too long
	//					if (pException != NULL)
	//					{
	//						pException->m_cause = CFileException::badPath;
	//						pException->m_strFileName = lpszFileIn;
	//					}
	//					return FALSE; // Path doesn't fit in the buffer.
	//				}
	//			}
	//			else
	//			{
	//				_AfxFillExceptionInfo(pException,lpszFileIn);
	//				return FALSE;
	//			}
	//		}
	//	}
	//}
	//
	return TRUE;
}
#endif

IMPLEMENT_DYNAMIC(CSandboxFile, CObject)
