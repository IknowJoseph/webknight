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
// ISAPIFirewall.h: interface for the CISAPIFirewall class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_ISAPIFIREWALL_H__E3402E9C_2ACB_45FF_AC12_09963674CD50__INCLUDED_)
#define AFX_ISAPIFIREWALL_H__E3402E9C_2ACB_45FF_AC12_09963674CD50__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "ISAPIFilter.h"
#include "HTTPFirewall.h"

//Errorhandling
#define ERROR_HANDLE				//use errorhandling in events (recommended)
#define DENY_ON_ERROR true			//protect the webserver at ALL costs, even when filter crashes! (recommended)

#define DO_READRAWDATA_EVENT		//comment/remove this line to disable OnReadRawData event (for custom build request, see e-mail of Paulo Molina)

//Debug logging
//#define LOG_DEBUG_ONREADRAWDATA	//log raw read data
//#define LOG_DEBUG_ONSENDRAWDATA	//log raw sent data (not recommended: performance impact!)


class CISAPIFirewall : public CISAPIFilter, public CHTTPFirewall  
{
public:
	virtual Action CustomHeaderScanning(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders, CString& ip, CURL& RawUrl, CString& ua, CString& version);
	Action ScanHeaders(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders);
	bool ScanResponseStatus(PHTTP_FILTER_CONTEXT pfc, LPCTSTR Status, bool& ResetFilterContext, bool& IsServerError, CString IP);
	
	CString GetClientIP(PHTTP_FILTER_CONTEXT pfc);
	void LogRequest(PHTTP_FILTER_CONTEXT pfc);
	inline void LogRequestLine(PHTTP_FILTER_CONTEXT pfc);
	inline void LogClientInfoExtra(PHTTP_FILTER_CONTEXT pfc);
	inline void LogClientInfo(PHTTP_FILTER_CONTEXT pfc);
	
	bool OnReadRawDataDebug(PHTTP_FILTER_CONTEXT pCtxt,PHTTP_FILTER_RAW_DATA pRawData);
	void SetFilterVersion(PHTTP_FILTER_VERSION pVer);
	void SendPage(PHTTP_FILTER_CONTEXT pfc, CString& Text, bool SendMessageBody = true, LPCTSTR ContentType = "text/html; charset=windows-1252");
	bool SendFile(PHTTP_FILTER_CONTEXT pfc, CString& Path, bool SendMessageBody = true, LPCTSTR ContentType = "text/html; charset=windows-1252", unsigned int MaxSize = 5000000);
	void HackResponse(PHTTP_FILTER_CONTEXT pfc, bool SendMessageBody = true, bool SendHeaders = true);

	//Admin
	void RunAdmin(PHTTP_FILTER_CONTEXT pfc, CFileName dll);
	virtual CString GetDynamicFile() { return ""; }
	bool ShowSettingsFile(PHTTP_FILTER_CONTEXT pfc, CString& Path, bool SendMessageBody = true);
	class _Intercept{
	public:
		CString Page;
		CString IP;
	} Intercept;

	//Hacks for known issues
	class _KnownIssues{
	public: 
		bool UrlMap;
		bool SkipSendRawData;
	} KnownIssues;
	
// Overrides
	// ClassWizard generated virtual function overrides
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//{{AFX_VIRTUAL(CISAPIFirewall)
	public:
	virtual DWORD OnReadRawData(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pRawData);
	virtual DWORD OnPreprocHeaders(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders);
	virtual DWORD OnAuthentication(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_AUTHENT pAuthent);
	virtual DWORD OnUrlMap(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_URL_MAP pUrlMap);
	virtual DWORD OnSendResponse(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE pResponse);
	virtual DWORD OnSendRawData(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pRawData);
	virtual DWORD OnLog(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_LOG pLog);
	virtual DWORD OnEndOfNetSession(PHTTP_FILTER_CONTEXT pfc);
	//}}AFX_VIRTUAL

	//{{AFX_MSG(CISAPIFirewall)
	//}}AFX_MSG

	CISAPIFirewall(CHTTPFirewallSettings& _Settings, CLogger& _logger);
	virtual ~CISAPIFirewall();

};

#endif // !defined(AFX_ISAPIFIREWALL_H__E3402E9C_2ACB_45FF_AC12_09963674CD50__INCLUDED_)
