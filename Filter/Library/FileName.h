/*
    AQTRONIX C++ Library
    Copyright 2002-2006 Parcifal Aertssen

    This file is part of AQTRONIX C++ Library.

    AQTRONIX C++ Library is free software; you can redistribute it
	and/or modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2 of
	the License, or (at your option) any later version.

    AQTRONIX C++ Library is distributed in the hope that it will be
	useful, but WITHOUT ANY WARRANTY; without even the implied warranty
    of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with AQTRONIX C++ Library; if not, write to the Free
    Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
    MA  02111-1307  USA
*/
// FileName.h: interface for the CFileName class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_FILENAME_H__15033FF3_3BB0_4580_8391_BEC06E684436__INCLUDED_)
#define AFX_FILENAME_H__15033FF3_3BB0_4580_8391_BEC06E684436__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CFileName : public CObject 
{
public:
	bool WriteStringToFile(CString& Contents);
	bool ReadFileToString(CString& Contents, ULONGLONG MaxSize = 5000000);
	static bool WriteStringToFile(CString& Contents, LPCTSTR fn);
	static bool ReadFileToString(LPCTSTR Path, CString& Contents, ULONGLONG MaxSize = 5000000);
	static CString GetDrivePrefix();

	void SetFileName(CString fn);
	
	bool Exists();
	bool DeleteFile();
	void CreatePath();
	static bool FileExists(LPCTSTR fn);
	static bool Exists(const CString& fn);
	static bool DeleteFile(const CString& fn);
	static void CreatePath(CString wsPath,LPSECURITY_ATTRIBUTES lpSecurityAttributes = NULL);

	CString FullPathLCase;
	CString FullPath;
	CString PathLCase;
	CString ExtensionLCase;
	CString FileNameLCase;
	CString Extension;
	CString FileName;
	CString Path;
	CFileName& CFileName::operator =(const CString& fn);
	CFileName(CString fn = _T(""));
	CFileName(const CFileName& fn);
	virtual ~CFileName();

};

#endif // !defined(AFX_FILENAME_H__15033FF3_3BB0_4580_8391_BEC06E684436__INCLUDED_)
