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
// ProcessHelper.cpp: implementation of the CProcessHelper class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ProcessHelper.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/* CHANGELOG
 *  2017.02.09 Unicode ready
 *  2016.10.19 Added GetCurrentPath
 *  2013.04.02 Fixed GetProcessPath for null termination if truncated (Windows XP only)
 *			   Added IgnoreExtended in GetProcessPath for ISAPI Extension
 *			   Added GetModulePath
 *			   Added GetCurrentModule hack because AfxGetInstanceHandle() 
 *					 does not work in constructor (before DllMain call)
 *  2012.12.30 Added GetErrorDescription(DWORD)
 *  2010.03.31 Added GetCurrentUserName()
 *	2005.09.02 Added GetErrorDescription(HRESULT)
 */

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CProcessHelper::CProcessHelper()
{

}

CProcessHelper::~CProcessHelper()
{

}

CString CProcessHelper::GetProcessPath(LPCTSTR ExeDllName, bool IgnoreExtended)
{
	return GetModulePath(GetModuleHandle(ExeDllName),IgnoreExtended);
}

CString CProcessHelper::GetModulePath(HMODULE handle, bool IgnoreExtended)
{
	TCHAR dir[MAX_PATH+1] = _T("");
	if(GetModuleFileName(handle,dir,MAX_PATH)){
		dir[MAX_PATH] = '\0'; //Windows XP not null terminated if truncated
		if(IgnoreExtended){
			CString fn(dir);
			fn.Replace(_T("\\\\?\\"),_T(""));//if loaded as ISAPI extension only (no filter) the path is \\?\C:\Program Files\AQTRONIX WebKnight\WebKnight.dll
			return fn;
		}
		return dir;
	}else{
		return _T("");
	}
}

CString CProcessHelper::GetCurrentPath()
{
	return GetModulePath(GetCurrentModule(),true);
}

HMODULE CProcessHelper::GetCurrentModule()
{
    MEMORY_BASIC_INFORMATION mbi = {0};
    ::VirtualQuery( GetCurrentModule, &mbi, sizeof(mbi) );

    return reinterpret_cast<HMODULE>(mbi.AllocationBase);
}

CString CProcessHelper::GetCurrentUserName()
{
	DWORD bufsize=255;
	TCHAR buf[256] = _T("\0");
	GetUserName(buf,&bufsize);
	return buf;
}

CString CProcessHelper::GetWindowsPath()
{
	TCHAR dir[MAX_PATH] = _T("");
	if(GetWindowsDirectory(dir,MAX_PATH)){
		return dir;
	}else{
		return _T("");
	}
}

CString CProcessHelper::GetErrorDescription(HRESULT hr)
{
	CString ret;
    if(FACILITY_WINDOWS == HRESULT_FACILITY(hr))
        hr = HRESULT_CODE(hr);
	LPTSTR szErrMsg = NULL;
    if(FormatMessage(   FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, 
						NULL, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
						(LPTSTR)&szErrMsg, 0, NULL) != 0) {
		ret = szErrMsg;
        LocalFree(szErrMsg);
    }else{
		ret = "[Could not determine error description] ";

		/*

		if(FormatMessage(   FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, 
							NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
							(LPTSTR)&szErrMsg, 0, NULL) != 0) {
			ret += szErrMsg;
			LocalFree(szErrMsg);
		}//*/

		/*
		if(IS_ERROR(hr)== S_OK){			ret="Operation successful";					}else{
		if(IS_ERROR(hr)== E_UNEXPECTED){	ret="Unexpected failure ";					}else{
		if(IS_ERROR(hr)== E_NOTIMPL){		ret="Not implemented";						}else{
		if(IS_ERROR(hr)== E_OUTOFMEMORY){	ret="Failed to allocate necessary memory";	}else{
		if(IS_ERROR(hr)== E_INVALIDARG){	ret="One or more arguments are invalid";	}else{
		if(IS_ERROR(hr)== E_NOINTERFACE){	ret="No such interface supported";			}else{
		if(IS_ERROR(hr)== E_POINTER){		ret="Invalid pointer";						}else{
		if(IS_ERROR(hr)== E_HANDLE){		ret="Invalid handle";						}else{
		if(IS_ERROR(hr)== E_ABORT){			ret="Operation aborted";					}else{
		if(IS_ERROR(hr)== E_FAIL){			ret="Unspecified failure";					}else{
		if(IS_ERROR(hr)== E_ACCESSDENIED){	ret="General access denied error";			
		}}}}}}}}}}}//*/

	}
	return ret;
}

CString CProcessHelper::GetErrorDescription(DWORD err_code)
{
	CString ret;
	LPTSTR szErrMsg = NULL;
    if(FormatMessage(   FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, 
						NULL, err_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
						(LPTSTR)&szErrMsg, 0, NULL) != 0) {
		ret = szErrMsg;
        LocalFree(szErrMsg);
		return ret;
    }else{
		return _T("[Could not determine error description]");
	}
}