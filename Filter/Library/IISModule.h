/*
    AQTRONIX C++ Library
    Copyright 2014-2015 Parcifal Aertssen

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
// IISModule.h: interface for the CIISModule class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_IISMODULE_H__4BF8F124_4F66_4530_A917_6431F405B01E__INCLUDED_)
#define AFX_IISMODULE_H__4BF8F124_4F66_4530_A917_6431F405B01E__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define _WINSOCKAPI_
#include <windows.h>
#include <sal.h>
#include <httpserv.h>

#include "StringHelper.h"
#include "HttpDataChunks.h"

class CIISModule : public CGlobalModule
{
public:
	VOID Terminate();
	void Error(LPCTSTR Message);

	CIISModule();
	virtual ~CIISModule();

protected:
	HRESULT SendPage(IHttpContext* pHttpContext, PCSTR Text);
	HRESULT WriteClient(IHttpContext* pHttpContext, PCSTR Text);
	CString GetRawDataWebKnight42(IN IPreBeginRequestProvider * pProvider, IHttpRequest* pHttpRequest);
	CString GetRawData(IN IPreBeginRequestProvider * pProvider, IHttpRequest* pHttpRequest);
	//TODO: MODULE - MaxHeaders collection without trailing ':'
	CString GetHeader(IHttpContext* pHttpContext, PCSTR Header /* without trailing ':' */);
	CString GetServerVariable(IHttpContext* pHttpContext, PCSTR Variable);

	// Event Log.
    HANDLE m_hEventLog;
    BOOL WriteEventLog(LPCSTR szNotification);
	BOOL WriteEventLog(LPCSTR szNotification, WORD wType, WORD wCategory, DWORD dwEventID);
};


#endif // !defined(AFX_IISMODULE_H__4BF8F124_4F66_4530_A917_6431F405B01E__INCLUDED_)
