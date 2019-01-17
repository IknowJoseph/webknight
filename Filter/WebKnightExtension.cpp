/*
    AQTRONIX C++ Library
    Copyright 2009-2013 Parcifal Aertssen

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
// WEBKNIGHTEXTENSION.CPP - Implementation file for your Internet Server
//    WebKnightExtension Extension

#include "stdafx.h"
#include "WebKnightExtension.h"

///////////////////////////////////////////////////////////////////////
// command-parsing map

//#pragma warning( disable : 4867)

//BEGIN_PARSE_MAP(CWebKnightExtension, CHttpServer)
//	// TODO: insert your ON_PARSE_COMMAND() and 
//	// ON_PARSE_COMMAND_PARAMS() here to hook up your commands.
//	// For example:
//
//	ON_PARSE_COMMAND(Default, CWebKnightExtension, ITS_EMPTY)
//	DEFAULT_PARSE_COMMAND(Default, CWebKnightExtension)
//END_PARSE_MAP(CWebKnightExtension)

///////////////////////////////////////////////////////////////////////
// CWebKnightExtension implementation

CWebKnightExtension::CWebKnightExtension(CWebKnightSettings& _Settings, CLogger& _logger):CHTTPFirewall(_Settings,_logger)
{
	//fix for GetErrorMessage not being able to load string resources
	AfxSetResourceHandle(CProcessHelper::GetCurrentModule());
	//AFX_MANAGE_STATE(AfxGetStaticModuleState( ));
}

CWebKnightExtension::~CWebKnightExtension()
{
}

BOOL CWebKnightExtension::GetExtensionVersion(HSE_VERSION_INFO* pVer)
{
	CSingleLock lock(&Settings.crit, TRUE);

	Message("INFO: Firewall will process raw data using a pass-through ISAPI extension.");

	// Call default implementation for initialization
	CISAPIExtension::GetExtensionVersion(pVer);

	// Load description string
	TCHAR sz[HSE_MAX_EXT_DLL_NAME_LEN+1];
	::LoadString(AfxGetResourceHandle(),IDS_EXTENSION, sz, HSE_MAX_EXT_DLL_NAME_LEN);
	_tcscpy(pVer->lpszExtensionDesc, sz);

	lock.Unlock();
	return TRUE;
}

BOOL CWebKnightExtension::TerminateExtension(DWORD dwFlags)
{
	// extension is being terminated
	// Clean up any per-instance resources
	return TRUE;
}

DWORD CWebKnightExtension::HttpExtensionProc(EXTENSION_CONTROL_BLOCK *pECB)
{
	/*
	 * IIS 5
	 * - Not supported, use global ISAPI filter functionality
	 *
	 * IIS 6
     * - Install as wildcard on "Web Sites" + inherit to all sites when asked
	 * - In ISAPI extensions set "All Unknown ISAPI Extensions" to Allowed
	 * OR
	 * - add an allowed ISAPI extension named "WebKnight"
	 *
	 */

	//return NotSupported(pECB);
	return PassThrough(pECB);
}
///////////////////////////////////////////////////////////////////////
// CWebKnightExtension command handlers

//void CWebKnightExtension::Default(CHttpServerContext* pCtxt)
//{
//	//StartContent(pCtxt);
//	//WriteTitle(pCtxt);
//	//*pCtxt << "This version of WebKnight does not support being loaded as an ISAPI extension. You should install WebKnight as an ISAPI filter instead.";
//	//EndContent(pCtxt);
//
//	//NotSupported(pCtxt->m_pECB);
//	//PassThrough(pCtxt->m_pECB);
//}

VOID WINAPI ExecuteUrlCompletionCallback(LPEXTENSION_CONTROL_BLOCK lpECB, PVOID pContext, DWORD cbIO, DWORD dwError)
{
	try{
		if(pContext!=NULL){
			HSE_EXEC_URL_STATUS hseExecUrlStatus;
			HSE_EXEC_UNICODE_URL_INFO* pHseExecUrlInfo = (HSE_EXEC_UNICODE_URL_INFO*)pContext;

			//
			// Set HTTP Status code on ISAPI so that logging works properly
			// cbIO and dwError should always be 0
			//
			if (!lpECB->ServerSupportFunction(lpECB->ConnID, HSE_REQ_GET_EXEC_URL_STATUS, &hseExecUrlStatus, NULL, NULL)){
				//
				// Was not able to fetch the HTTP Status codes.  Won't log any ISAPI failures for this
				//
			}else{
				//
				// Must set lpECB->dwHttpStatusCode or else logging is incorrectly always 200
				// Should propagate hseExecUrlStatus.dwWin32Error if I don't do anything about it
				//
				lpECB->dwHttpStatusCode = hseExecUrlStatus.uHttpStatusCode;
				SetLastError( hseExecUrlStatus.dwWin32Error );
			}

			DWORD dwStatusType = HSE_STATUS_SUCCESS;
			lpECB->ServerSupportFunction(lpECB->ConnID, HSE_REQ_DONE_WITH_SESSION, &dwStatusType, NULL, NULL);


			delete pHseExecUrlInfo;
		}
	}catch(...){
		//do nothing
	}
}

DWORD CWebKnightExtension::PassThrough(EXTENSION_CONTROL_BLOCK* pECB)
{
	try{
		// http://msdn.microsoft.com/en-us/library/ms525758%28v=vs.90%29.aspx

		//http://support.microsoft.com/kb/919789

		HSE_EXEC_UNICODE_URL_INFO* pHseExecUrlInfo = new HSE_EXEC_UNICODE_URL_INFO();
		if(NULL==pHseExecUrlInfo){
			SendResponse(pECB,"Out of memory");
			return HSE_STATUS_ERROR;			
		}else{
			ZeroMemory(pHseExecUrlInfo, sizeof(HSE_EXEC_UNICODE_URL_INFO));
			pHseExecUrlInfo->dwExecUrlFlags = HSE_EXEC_URL_IGNORE_CURRENT_INTERCEPTOR;
			if(!pECB->ServerSupportFunction(pECB->ConnID, HSE_REQ_IO_COMPLETION, ExecuteUrlCompletionCallback , NULL, (LPDWORD)pHseExecUrlInfo)){
				delete pHseExecUrlInfo;
				SendResponse(pECB,"WebKnight ISAPI Extension: This version of IIS does not support HSE_REQ_IO_COMPLETION, use WebKnight as an ISAPI filter instead.");
				return HSE_STATUS_ERROR;
			}
		}

		if(OnPassThrough(pECB)){
			//allow execution
			if(pECB->ServerSupportFunction(pECB->ConnID, HSE_REQ_EXEC_UNICODE_URL, pHseExecUrlInfo, NULL, NULL)){
				return HSE_STATUS_PENDING;
			}else{
				DWORD uErr = GetLastError();
				TCHAR szError[512];
				wsprintf(szError, "WebKnight ISAPI Extension: This version of IIS does not support HSE_REQ_EXEC_UNICODE_URL, use WebKnight as an ISAPI filter instead. (Error: %d)", uErr);
				SendResponse(pECB,szError);
				CSingleLock lock(&Settings.crit, TRUE);
				lock.Lock();
				logger.NewEntryFlush(szError);
				lock.Unlock();
				return HSE_STATUS_ERROR;
			}
		}else{
			//don't use HSE_STATUS_SUCCESS_AND_KEEP_CONN (HSE_STATUS_SUCCESS keeps connection open)
			//http://microsoft.public.platformsdk.internet.server.isapi-dev.narkive.com/NCPoqTzQ/pros-and-cons-of-passing-hse-status-success-and-keep-conn-as-a-value-of-hse-req-done-with-session
			return HSE_STATUS_SUCCESS;			//make sure IIS does nothing with request
		}

	}catch(...){
		Message("Fatal error in WebKnight ISAPI Extension");
		return HSE_STATUS_ERROR;
	}
}

bool CWebKnightExtension::OnPassThrough(EXTENSION_CONTROL_BLOCK* pECB)
{
	CString instance = GetServerVariable(pECB,"INSTANCE_ID");
	CString url(GetServerVariable(pECB,"SCRIPT_NAME"));

	CSingleLock lock(&Settings.crit, TRUE);

	logger.NewEntry(SITEINSTANCE + instance);
	logger.Append("OnPassThrough");

	LogClientInfo(pECB);
	LogRequestLine(pECB);

	bool logonly(Settings.Response.LogOnly);
	bool respdrop(Settings.HTTPResponse.DropConnection);
	Action action;
	bool IsHEADRequest = (GetServerVariable(pECB,"REQUEST_METHOD")=="HEAD");

	CString IP(GetClientIP(pECB));
	if(!IsExcludedSite(instance) && !IsExcludedIP(IP)){
		if(Settings.Admin.Enabled && Settings.IPRanges.Admin.IsInList(IP) && url.Left(Settings.Admin.Url.GetLength())==Settings.Admin.Url){
			//excluded from scanning

		}else{
			//excluded url+querystring or host
			if(!IsExcludedURL(url,CString(pECB->lpszQueryString)) && !IsExcludedHost(GetServerVariable(pECB,"HTTP_HOST")) && !IsExcludedUserAgent(GetServerVariable(pECB,"HTTP_USER_AGENT"))){

				//HEADERS
				//action |= ScanRawHeaders(strh); //ignore, extension only used to scan post data
				//DATA
				//prepare the raw data before processing
				CString strd = GetRawData(pECB);
				//CFileName::WriteStringToFile(strd,"C:\\Debug\\postdata.txt");
				if(strd.GetLength()>0){
					CString ContentType(GetServerVariable(pECB,"HTTP_CONTENT_TYPE"));
					logger.Append(ContentType);
					action |= ScanEntity(strd, ContentType, IP);
				}
				
				//CONNECTION - Monitoring
				if(Settings.Connection.MonitorAddresses.Enabled && strd.GetLength()>0){
					if(Settings.IPRanges.Monitor.IsInList(IP)){
						logger.Append("MONITORED: IP address '" + IP + "'");
						logger.AppendEscape(strd);
						logger.Flush();
					}
				}
			}
		}
	}

	//no more code here logger.Flush() may already be called

	//block or monitor IP (rule action)
	if(action.Status[Action::MonitorIP]){
		Statistics.IP_HACK_Monitored.AddNotInCache(IP);
		action.Set(Action::Monitor);
	}
	if(action.Status[Action::BlockIP]){
		Statistics.IP_HACK_Blocked.Add(IP);
		action.Set(Action::Block);
	}
	//if possible hack attempt
	if(action.Status[Action::Block]){
		logger.Flush();								//flush the log entry
		HackResponseBlockOrMonitor(IP);				//block or monitor IP address
		if(!logonly)								//if we have to do more than logging
			HackResponse(pECB,!IsHEADRequest);		//show page
		lock.Unlock();								//unlock globals
		if(logonly){								//if we are only here to log
			return true;							//allow execution by IIS
		}else{										//if we have to do more than logging
			if(respdrop){
				pECB->ServerSupportFunction(pECB->ConnID, HSE_REQ_CLOSE_CONNECTION, NULL, NULL, NULL);
			}
			return false;							//make sure IIS does nothing with request
		}
	}else{
		if((action.Status[Action::Monitor] || Settings.Logging.LogAllowed) && logger.HasEntry()){//do not log allowed requests if asked
			logger.Append("ALLOWED");
			logger.Flush();
		}else{
			logger.Cancel();						//clear the log entry
		}
		lock.Unlock();								//unlock globals
		return true;
	}
}

DWORD CWebKnightExtension::NotSupported(EXTENSION_CONTROL_BLOCK* pECB)
{
	//StartContent(pCtxt);
	//WriteTitle(pCtxt);
	SendResponse(pECB,"This version of WebKnight does not support being loaded as an ISAPI extension. You should install WebKnight as an ISAPI filter instead.");	
	//EndContent(pCtxt);
	return HSE_STATUS_SUCCESS;
}

inline void CWebKnightExtension::LogClientInfo(EXTENSION_CONTROL_BLOCK *pECB)
{
	if(Settings.Logging.LogClientIP) logger.Append(GetClientIP(pECB));
	if(Settings.Logging.LogUserName) logger.Append(GetServerVariable(pECB,"LOGON_USER"));
	if(Settings.HTTPLogging.Log_HTTP_VIA) logger.Append(GetServerVariable(pECB,"HTTP_VIA"));
	if(Settings.HTTPLogging.Log_HTTP_X_FORWARDED_FOR) logger.Append(GetServerVariable(pECB,"HTTP_X_FORWARDED_FOR"));
	if(Settings.HTTPLogging.LogHostHeader) logger.Append(GetServerVariable(pECB,"HTTP_HOST"));
	if(Settings.HTTPLogging.LogUserAgent) logger.Append(GetServerVariable(pECB,"HTTP_USER_AGENT"));
}

inline void CWebKnightExtension::LogRequestLine(EXTENSION_CONTROL_BLOCK *pECB)
{
	logger.Append(GetServerVariable(pECB,"REQUEST_METHOD"));
	logger.Append(GetServerVariable(pECB,"SCRIPT_NAME"));
	logger.Append(GetServerVariable(pECB,"PATH_INFO"));
	logger.Append(GetServerVariable(pECB,"QUERY_STRING"));
}

CString CWebKnightExtension::GetClientIP(EXTENSION_CONTROL_BLOCK *pECB)
{
	CString IP("");
	//get custom header like X-Forwarded-For
	if(Settings.Connection.ClientIPVariable.GetLength()>0){
		IP = GetServerVariable(pECB,Settings.Connection.ClientIPVariable.GetBuffer(0));
		//if multiple X-Forwarded-For headers are present, only use the last one, others can be spoofed
		int pos = IP.ReverseFind(',');
		if(pos>-1 && pos<IP.GetLength()){
			IP = IP.Mid(pos+1,IP.GetLength()-pos-1).Trim();
		}
	}
	//get standard header if custom header is not present
	if(IP == ""){
		IP = GetServerVariable(pECB,REMOTE_ADDR);
	}
	return IP;
}

void CWebKnightExtension::HackResponse(EXTENSION_CONTROL_BLOCK *pECB, bool SendMessageBody)
{
	if(Settings.HTTPResponse.Directly){
		//direct response to client (writeclient)
		SendResponse(pECB,GetAlertResponse(SendMessageBody));
	}else if(Settings.HTTPResponse.Redirect){
		//redirect request to a url
		CString buf = Settings.HTTPResponse.RedirectURL;
		DWORD szbuf(buf.GetLength());
		pECB->ServerSupportFunction(pECB,HSE_REQ_SEND_URL_REDIRECT_RESP,buf.GetBuffer(0),&szbuf,NULL);
	}else if(Settings.HTTPResponse.UseStatus){
		//respond with special header only
		pECB->ServerSupportFunction(pECB,HSE_REQ_SEND_RESPONSE_HEADER,(LPVOID)(LPCTSTR)Settings.HTTPResponse.Status,NULL,NULL);
	}
}

// Do not edit the following lines, which are needed by ClassWizard.
#if 0
BEGIN_MESSAGE_MAP(CWebKnightExtension, CHttpServer)
	//{{AFX_MSG_MAP(CWebKnightExtension)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()
#endif	// 0



///////////////////////////////////////////////////////////////////////
// If your extension will not use MFC, you'll need this code to make
// sure the extension objects can find the resource handle for the
// module.  If you convert your extension to not be dependent on MFC,
// remove the comments arounn the following AfxGetResourceHandle()
// and DllMain() functions, as well as the g_hInstance global.

/****

static HINSTANCE g_hInstance;

HINSTANCE AFXISAPI AfxGetResourceHandle()
{
	return g_hInstance;
}

BOOL WINAPI DllMain(HINSTANCE hInst, ULONG ulReason,
					LPVOID lpReserved)
{
	if (ulReason == DLL_PROCESS_ATTACH)
	{
		g_hInstance = hInst;
	}

	return TRUE;
}

****/
