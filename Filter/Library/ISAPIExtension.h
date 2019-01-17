/*
    AQTRONIX C++ Library
    Copyright 2005-2012 Parcifal Aertssen

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
// ISAPIExtension.h: interface for the CISAPIExtension class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_ISAPIEXTENSION_H__4BF8F124_4F66_4530_A917_6431F405B01E__INCLUDED_)
#define AFX_ISAPIEXTENSION_H__4BF8F124_4F66_4530_A917_6431F405B01E__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <httpext.h>
#include "StringHelper.h"

//Headers
#define MAX_HEADER_SIZE	96000		//the maximum header size
#define MIN_HEADER_SIZE 4128		//average minimum header size: for best performance choose a min header size large enough for most header values.

class CISAPIExtension
{
public:
	CISAPIExtension();
	virtual ~CISAPIExtension();

	//entry functions
	virtual BOOL GetExtensionVersion(HSE_VERSION_INFO *pVer);
	virtual DWORD HttpExtensionProc(EXTENSION_CONTROL_BLOCK *pECB);
	virtual BOOL TerminateExtension(DWORD dwFlags);
	//VOID ExecuteUrlCompletionCallback(LPEXTENSION_CONTROL_BLOCK lpECB, PVOID pContext, DWORD cbIO, DWORD dwError);
	
	//helper functions
	CString GetServerVariable(EXTENSION_CONTROL_BLOCK *pECB,LPTSTR sv);
	void SendResponse(EXTENSION_CONTROL_BLOCK* pECB, CString Message);
	CString GetRawData(EXTENSION_CONTROL_BLOCK* pECB);
};

#endif // !defined(AFX_ISAPIEXTENSION_H__4BF8F124_4F66_4530_A917_6431F405B01E__INCLUDED_)
