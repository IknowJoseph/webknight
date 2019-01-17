/*
    AQTRONIX C++ Library
    Copyright 2005-2013 Parcifal Aertssen

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
// ProcessHelper.h: interface for the CProcessHelper class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PROCESSHELPER_H__27C097A6_84F8_4EB8_BC31_7BC9CA5DB1E0__INCLUDED_)
#define AFX_PROCESSHELPER_H__27C097A6_84F8_4EB8_BC31_7BC9CA5DB1E0__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CProcessHelper  
{
public:
	static CString GetErrorDescription(DWORD err_code);
	static CString GetErrorDescription(HRESULT hr);
	static CString GetWindowsPath();
	static CString GetProcessPath(LPCTSTR ExeDllName = NULL, bool IgnoreExtended = false);
	static CString GetModulePath(HMODULE handle = NULL, bool IgnoreExtended = false);
	static CString GetCurrentPath();
	static HMODULE GetCurrentModule();
	static CString GetCurrentUserName();

	CProcessHelper();
	virtual ~CProcessHelper();

};

#endif // !defined(AFX_PROCESSHELPER_H__27C097A6_84F8_4EB8_BC31_7BC9CA5DB1E0__INCLUDED_)
