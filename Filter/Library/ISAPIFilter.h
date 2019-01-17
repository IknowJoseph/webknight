/*
    AQTRONIX C++ Library
    Copyright 2005-2006 Parcifal Aertssen

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
#if !defined(AFX_ISAPIFILTER_H__05615D36_F4FB_4F6F_BF2B_68B61F10CB94__INCLUDED_)
#define AFX_ISAPIFILTER_H__05615D36_F4FB_4F6F_BF2B_68B61F10CB94__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// ISAPIFilter.h : header file
//
#include "httpfilt.h"

//Headers
#define MAX_HEADER_SIZE	96000		//the maximum header size
#define MIN_HEADER_SIZE 4128		//average minimum header size: for best performance choose a min header size large enough for most header values.

#define CR '\r'
#define LF '\n'
#define CRLF "\r\n"
#define CRLFCRLF "\r\n\r\n"

#define CONTEXT_NEW_REQUEST				NULL
#define CONTEXT_SLOW_HEADER				(VOID *)1
#define CONTEXT_SLOW_HEADER_SKIP_ONE	(VOID *)2
#define CONTEXT_HEADERS_RECEIVED		(VOID *)3
#define CONTEXT_SLOW_POST				(VOID *)4
#define CONTEXT_SENDING_RESPONSE		(VOID *)10	//request ended
#define CONTEXT_SENDING_REDIRECT		(VOID *)11
#define CONTEXT_SENDING_HEADERS			(VOID *)12
#define CONTEXT_SENDING_DATA			(VOID *)13
#define CONTEXT_SENDING_LOG				(VOID *)14
#define CONTEXT_SENDING_TEXT			(VOID *)15
#define CONTEXT_SENDING_ALERT			(VOID *)16
#define CONTEXT_MAX						(VOID *)16	//if higher than this it is not a context, but memory allocation

/////////////////////////////////////////////////////////////////////////////
// CISAPIFilter command target

class CISAPIFilter
{
// Attributes
public:

// Operations
public:
	virtual DWORD HttpFilterProc(PHTTP_FILTER_CONTEXT pfc, DWORD dwNotificationType, LPVOID pvNotification);
	virtual BOOL GetFilterVersion(PHTTP_FILTER_VERSION pVer);

	virtual DWORD OnReadRawData(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pRawData);
	virtual DWORD OnPreprocHeaders(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders);
	virtual DWORD OnAuthentication(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_AUTHENT pAuthent);
	virtual DWORD OnUrlMap(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_URL_MAP pUrlMap);
	virtual DWORD OnSendRawData(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pRawData);
	virtual DWORD OnLog(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_LOG pLog);
	virtual DWORD OnEndOfNetSession(PHTTP_FILTER_CONTEXT pfc);
	virtual DWORD OnEndOfRequest(PHTTP_FILTER_CONTEXT pfc);
	virtual DWORD OnAuthComplete(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_AUTH_COMPLETE_INFO pAuthComplInfo);
	virtual DWORD OnSendResponse(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE pResponse);
	virtual DWORD OnAccessDenied(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_ACCESS_DENIED pAccessDenied);

	void PrepareRawData(PHTTP_FILTER_CONTEXT pfc, CString& RawData, CString& Headers, CString& Data);
	bool ChangeHeader(CString& RawData, LPCTSTR Header, LPCTSTR Value, bool RemoveHeader = false);
	bool ChangeHeader(CString& RawData, CMapStringToString& map);
	bool ChangeHeader(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE pResponse, CMapStringToString& map);
	CString GetHeader(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders, char* h);
	CString GetServerVariable(PHTTP_FILTER_CONTEXT pfc,LPTSTR sv);
	CString SerializeRequest(PHTTP_FILTER_CONTEXT pfc);
	void SendData(PHTTP_FILTER_CONTEXT pfc, CString& Response);

	bool IsIIS7ProblemResponse(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE pResponse);
	bool IsWebsocketsUpgrade(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE pResponse);

	CISAPIFilter();
	virtual ~CISAPIFilter();

// Overrides
public:
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CISAPIFilter)
	//}}AFX_VIRTUAL

	// Generated message map functions
	//{{AFX_MSG(CISAPIFilter)
		// NOTE - the ClassWizard will add and remove member functions here.
	//}}AFX_MSG

// Implementation
protected:
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_ISAPIFILTER_H__05615D36_F4FB_4F6F_BF2B_68B61F10CB94__INCLUDED_)
