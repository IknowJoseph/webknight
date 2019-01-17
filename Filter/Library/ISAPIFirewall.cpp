/*
    AQTRONIX C++ Library
    Copyright 2005-2015 Parcifal Aertssen

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
// ISAPIFirewall.cpp: implementation of the CISAPIFirewall class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ISAPIFirewall.h"
#include "Base64.h"
#include "MIME.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CISAPIFirewall::CISAPIFirewall(CHTTPFirewallSettings& _Settings, CLogger& _logger):CHTTPFirewall(_Settings,_logger)
{

}

CISAPIFirewall::~CISAPIFirewall()
{

}

DWORD CISAPIFirewall::OnReadRawData(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pRawData)
{

#ifdef ERROR_HANDLE
	try{
#endif

	/*
	 * This event is only available if the filter is installed as a global
	 * filter (not on individual web sites) and will only be called if
	 * IsInstalledAsGlobalFilter=1
	 * WARNING: if the value is set to 1 and the filter is not installed as
	 * a global filter then IIS will not load the filter (red arrow down)!
	 */

	if(pfc!=NULL && pRawData!=NULL){

		//cleanup heap allocation from OnLog event
		if(Settings.Connection.ChangeLogIPVariable && pfc->pFilterContext>CONTEXT_MAX){
			delete (CString*)pfc->pFilterContext;
			pfc->pFilterContext = NULL;
		}


		CSingleLock lock(&Settings.crit, TRUE);

		//reset keep-alive context
		if(pfc->pFilterContext!=CONTEXT_NEW_REQUEST && pfc->pFilterContext>CONTEXT_SENDING_RESPONSE){
			pfc->pFilterContext=CONTEXT_NEW_REQUEST;
		}

#ifdef LOG_DEBUG_ONREADRAWDATA
		OnReadRawDataDebug(pfc,pRawData);
#endif

		logger.NewEntry("GLOBAL");
		logger.Append("OnReadRawData");
		LogClientInfo(pfc);

		bool logonly(Settings.Response.LogOnly);
		bool respdrop(Settings.HTTPResponse.DropConnection);
		Action action;

		CString IP(GetClientIP(pfc));
		if(!IsExcludedIP(IP) && !(Settings.Admin.Enabled && Settings.Admin.AllowConfigChanges && Settings.IPRanges.Admin.IsInList(IP)) ){//Allow Admin POST requests too 
			//prepare the raw data before processing
			CString Raw = ConvertBinaryData((BYTE*)pRawData->pvInData,pRawData->cbInData,' ');

			CString strh;				//for headers
			CString strd;				//for post data

			PrepareRawData(pfc,Raw,strh,strd);

	#ifdef LOG_DEBUG_ONREADRAWDATA
			logger.Append("\r\nRaw data:");		logger.Append(Raw);
			//logger.Append("\r\nHeaders:");	logger.Append(strh);
			//logger.Append("\r\nData:");		logger.Append(strd);
	#endif

			//HEADERS
			if(strh.GetLength()>0){
				action |= ScanRawHeaders(strh);

				//HTTP Slow header attack
				if(Settings.Global.SlowHeaderAttack && strd.GetLength()==0){
					if(pfc->pFilterContext==CONTEXT_SLOW_HEADER){
						if(action.IsEmpty()){
							logger.AppendEscape(strh.Left(1024));
						}
						action.Set(Settings.Global.SlowHeaderAttack);
						Alert("Slow header attack detected",Settings.Global.SlowHeaderAttack);
					}
					if(pfc->pFilterContext==CONTEXT_SLOW_HEADER_SKIP_ONE){
						//block the next slow header
						pfc->pFilterContext=CONTEXT_SLOW_HEADER;
					}else{
						//skip one slow header to avoid false positives
						pfc->pFilterContext=CONTEXT_SLOW_HEADER_SKIP_ONE;
					}
				}
			}
			//DATA
			if(strd.GetLength()>0){
				//scan data
				action |= ScanRawData(strd, IP);

				//HTTP Slow POST attack
				if(Settings.Global.SlowPostAttack && strd.GetLength()<100 && GetServerVariable(pfc,"REQUEST_METHOD")=="POST"){
					CString ContentLength = GetServerVariable(pfc,"HTTP_CONTENT_LENGTH");
					if(ContentLength.GetLength()>2){
						if(pfc->pFilterContext==CONTEXT_SLOW_POST){
							action.Set(Settings.Global.SlowPostAttack);
							Alert("Slow POST attack detected (" + CStringHelper::Safe_LongToAscii(strd.GetLength()) + " bytes received of Content-Length: " + ContentLength.Left(23) + ")",Settings.Global.SlowPostAttack);
						}
						pfc->pFilterContext=CONTEXT_SLOW_POST;
					}
				}
			}

			//CONNECTION - Monitoring
			if(Settings.Connection.MonitorAddresses.Enabled){
				if(Settings.IPRanges.Monitor.IsInList(IP)){
					logger.Append("MONITORED: IP address '" + IP + "'");
					logger.AppendEscape(Raw);
					logger.Flush();
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
				HackResponse(pfc);						//show page (BUGS: server header not removed & possible loop)
			lock.Unlock();								//unlock globals
			if(logonly){								//if we are only here to log
				return SF_STATUS_REQ_NEXT_NOTIFICATION;
			}else{										//if we have to do more than logging
				if(respdrop){
					return SF_STATUS_REQ_FINISHED;		//make sure IIS does nothing with request
				}else{
					return SF_STATUS_REQ_FINISHED_KEEP_CONN;//make sure IIS does nothing with request
				}
			}
		}else{
			if((action.Status[Action::Monitor] || Settings.Logging.LogAllowed) && logger.HasEntry()){//do not log allowed requests if asked
				logger.Append("ALLOWED");
				logger.Flush();
			}else{
				logger.Cancel();						//clear the log entry
			}
			lock.Unlock();								//unlock globals
			return SF_STATUS_REQ_NEXT_NOTIFICATION;
		}
	}
	return CISAPIFilter::OnReadRawData(pfc,pRawData);

#ifdef ERROR_HANDLE
	}catch(...){
		if(DENY_ON_ERROR){							//deny request on error if asked
			return SF_STATUS_REQ_FINISHED;			//don't keep connection, because of error
		}else{
			return SF_STATUS_REQ_NEXT_NOTIFICATION;
		}
	}
#endif
}

DWORD CISAPIFirewall::OnPreprocHeaders(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders)
{
#ifdef ERROR_HANDLE
	try{
#endif

	if(pfc!=NULL && pHeaders!=NULL){
		CString instance = GetServerVariable(pfc,"INSTANCE_ID");
		CString host(GetHeader(pfc,pHeaders,"Host:"));

		//cleanup heap allocation from OnLog event
		if(Settings.Connection.ChangeLogIPVariable && pfc->pFilterContext>CONTEXT_MAX){
			delete (CString*)pfc->pFilterContext;
		}

		//mark all headers received
		pfc->pFilterContext = CONTEXT_HEADERS_RECEIVED;

		CSingleLock lock(&Settings.crit, TRUE);
		
		UpdateSettings();
		
		logger.NewEntry(SITEINSTANCE + instance);
		logger.Append("OnPreprocHeaders");
		LogClientInfo(pfc);
		
		Action action;
		bool IsHEADRequest(false);
		bool logonly(Settings.Response.LogOnly);
		bool respdrop(Settings.HTTPResponse.DropConnection);
		bool is_blacklisted(false);

		CString IP(GetClientIP(pfc));
		if(!IsExcludedSite(instance) && !IsExcludedIP(IP)){

			//excluded url+querystring or host
			CURL RawUrl(GetHeader(pfc,pHeaders,"url"));
			CString ua(GetHeader(pfc,pHeaders,"User-Agent:"));
			if(IsExcludedURL(RawUrl.Url,RawUrl.Querystring) || IsExcludedHost(host) || IsExcludedUserAgent(ua)){
				
				//done with processing notifications for this request
				logger.Append("Further event notifications are disabled for this request");
				pfc->pFilterContext = CONTEXT_NEW_REQUEST;
				//disable further notifications for this request
				pfc->ServerSupportFunction(pfc,SF_REQ_DISABLE_NOTIFICATIONS,NULL,
					SF_NOTIFY_READ_RAW_DATA|
					SF_NOTIFY_PREPROC_HEADERS|
					SF_NOTIFY_AUTHENTICATION|
					SF_NOTIFY_URL_MAP|
					SF_NOTIFY_SEND_RESPONSE|
					SF_NOTIFY_SEND_RAW_DATA,NULL);

			}else{
				CString Verb(GetHeader(pfc,pHeaders,"method"));
				CString ContentLength(GetHeader(pfc,pHeaders,"Content-Length:"));
				CString ContentType(GetHeader(pfc,pHeaders,"Content-Type:"));
				CString TransferEncoding(GetHeader(pfc,pHeaders,"Transfer-Encoding:"));
				IsHEADRequest = (Verb=="HEAD"); //do not send message body if HEAD request (RFC compliant)
	
				//VERB
				action |= ScanVerb(Verb, ContentLength, ContentType, TransferEncoding);

				//RAWURL
				action |= ScanRawURL(RawUrl,IP);

				//VERSION
				CString version = GetHeader(pfc,pHeaders,"version");
				action |= ScanVersion(version);

				//HOST
				action |= ScanHost(version,host,IP);

				//HEADERS: raw headers
				action |= ScanRawHeaders(GetServerVariable(pfc,"ALL_RAW"));

				//HEADERS: denied list / length
				action |= ScanHeaders(pfc,pHeaders);

				//HEADERS: content length / type
				if(! (Settings.Admin.Enabled && Settings.IPRanges.Admin.IsInList(IP) && RawUrl.StartsWith(Settings.Admin.Url)) ) //skip webknight admin when editing config file: BLOCKED: Content-Length is too long (application/x-www-form-urlencoded>49152)
					action |= ScanContent(ContentType,ContentLength);

				//HEADERS: transfer encoding
				if(TransferEncoding.GetLength()>0)
					action |= ScanTransferEncoding(TransferEncoding);

				//COOKIE
				action |= ScanCookie(GetHeader(pfc,pHeaders,"Cookie:"),IP,ua,RawUrl.Url);

				//REFERRER
				CString ref = GetHeader(pfc,pHeaders,"Referer:");
				if(!IsExcludedReferrerURL(ref))
					action |= ScanRawReferrerURL(ref,CURL::Decode(RawUrl.Url),host,ua);

				//Custom header scanning (virtual function)
				action |= CustomHeaderScanning(pfc,pHeaders,IP,RawUrl,ua,version);

				//AUTH
				if(Settings.Authentication.ScanAccountAllEvents){
					action |= ScanAccount(GetServerVariable(pfc,"LOGON_USER"));
				}

				//CONNECTION
				bool is_monitored(false);
				action |= ScanConnection(IP,is_blacklisted,is_monitored);

				if(is_monitored){	//monitored connection
					LogClientInfoExtra(pfc);
					logger.Flush();
				}

				//no further code here (reason: logger already flushed if is_monitored)
			}
		}

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
			if(!is_blacklisted){
				HackResponseBlockOrMonitor(IP);			//block or monitor IP address
			}
			if(!logonly){								//if we have to do more than logging
				HackResponse(pfc,!IsHEADRequest);		//show page

				if(KnownIssues.UrlMap){
					pfc->ServerSupportFunction(pfc, SF_REQ_DISABLE_NOTIFICATIONS, NULL, SF_NOTIFY_URL_MAP, NULL); //needed for IIS 8 race condition which results in stack overflow
				}
			}
			lock.Unlock();								//unlock globals
			if(logonly){								//if we are only here to log
				return CISAPIFilter::OnPreprocHeaders(pfc, pHeaders);
			}else{										//if we have to do more than logging
				if(respdrop){
					return SF_STATUS_REQ_FINISHED;		//make sure IIS does nothing with request
				}else{
					return SF_STATUS_REQ_FINISHED_KEEP_CONN;//make sure IIS does nothing with request
				}
			}
		}else{
			if((action.Status[Action::Monitor] || Settings.Logging.LogAllowed) && logger.HasEntry()){//do not log allowed requests if asked
				logger.Append("ALLOWED");
				logger.Flush();						
			}else{
				logger.Cancel();						//clear the log entry
			}
			lock.Unlock();								//unlock globals
			return CISAPIFilter::OnPreprocHeaders(pfc, pHeaders);
		}
	}
	return CISAPIFilter::OnPreprocHeaders(pfc, pHeaders);

#ifdef ERROR_HANDLE
	}catch(...){
		if(DENY_ON_ERROR){							//deny request on error if asked
			return SF_STATUS_REQ_FINISHED;			//don't keep connection, because of error
		}else{
			return CISAPIFilter::OnPreprocHeaders(pfc, pHeaders);
		}
	}
#endif
}

DWORD CISAPIFirewall::OnAuthentication(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_AUTHENT pAuthent)
{
	/*
		CHAR*    pszUser;                           //IN/OUT
		DWORD    cbUserBuff;                        //IN
		CHAR*    pszPassword;                       //IN/OUT
		DWORD    cbPasswordBuff;                    //IN
	*/

#ifdef ERROR_HANDLE
	try{
#endif

	if(pfc!=NULL && pAuthent!=NULL){
		CString instance = GetServerVariable(pfc,"INSTANCE_ID");

		CSingleLock lock(&Settings.crit, TRUE);

		logger.NewEntry(SITEINSTANCE + instance);
		logger.Append("OnAuthentication");
		LogClientInfo(pfc);

		Action action;
		bool logonly(Settings.Response.LogOnly);
			
		CString IP(GetClientIP(pfc));
		if( (Settings.Authentication.ScanExcludedInstances || !IsExcludedSite(instance)) && !IsExcludedIP(IP) ){
			if(pAuthent->cbUserBuff==0 || pAuthent->cbPasswordBuff==0){
				//logger.Append("WARNING: There is a mistake in the MSDN!");
			}else{

				CString User(pAuthent->pszUser);
				CString Pass(pAuthent->pszPassword);

				if(User!="")
					action |= ScanAuthentication(User,Pass,IP);
			}
		}
	
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
				HackResponse(pfc);						//show page
			lock.Unlock();								//unlock globals
			if(logonly){								//if we are only here to log
				return CISAPIFilter::OnAuthentication(pfc, pAuthent);
			}else{										//if we have to do more than logging
				return SF_STATUS_REQ_FINISHED;			//make sure IIS does nothing with request (always drop connection)
			}
		}else{
			if((action.Status[Action::Monitor] || Settings.Logging.LogAllowed) && logger.HasEntry()){//do not log allowed requests if asked
				logger.Append("ALLOWED");
				logger.Flush();	
			}else{
				logger.Cancel();						//clear the log entry
			}
			lock.Unlock();								//unlock globals
			return CISAPIFilter::OnAuthentication(pfc, pAuthent);
		}
	}
	return CISAPIFilter::OnAuthentication(pfc, pAuthent);

#ifdef ERROR_HANDLE
	}catch(...){
		if(DENY_ON_ERROR){							//deny request on error if asked
			return SF_STATUS_REQ_FINISHED;			//don't keep connection, because of error
		}else{
			return CISAPIFilter::OnAuthentication(pfc, pAuthent);
		}
	}
#endif
}

DWORD CISAPIFirewall::OnUrlMap(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_URL_MAP pUrlMap) 
{
#ifdef ERROR_HANDLE
	try{
#endif

	if(pfc!=NULL && pUrlMap!=NULL){
		CString instance = GetServerVariable(pfc,"INSTANCE_ID");

		CSingleLock lock(&Settings.crit, TRUE);

		logger.NewEntry(SITEINSTANCE + instance);
		logger.Append("OnUrlMap");
		LogClientInfo(pfc);

		Action action;
		bool logonly(Settings.Response.LogOnly);
		bool respdrop(Settings.HTTPResponse.DropConnection);
		CURL u(pUrlMap->pszURL);
	
		CString IP(GetClientIP(pfc));
		if(!IsExcludedSite(instance) && !IsExcludedIP(IP)){
			//URL Scanning
			if(pUrlMap->pszURL!=NULL){
				CString url(pUrlMap->pszURL);
				logger.Append(url.Left(9000));
				if(url.GetLength()>0){
					action |= ScanURL(pUrlMap->pszURL);

					if(!Settings.URL.UseRawScan){//if not already counted for in OnPreprocHeaders
						action |= ScanURLDoS(url);
					}
				}
			}
		
			//PATH
			CFileName fn(pUrlMap->pszPhysicalPath);
			action |= ScanPath(fn);

			if(!Settings.Global.IsInstalledAsGlobalFilter){//if not already counted for in OnPreprocHeaders
				action |= ScanExtensionDoS(fn.ExtensionLCase,IP);
			}
			
			//QUERYSTRING
			action |= ScanQuerystring(GetServerVariable(pfc,"QUERY_STRING"),!u.StartsWith(Settings.Admin.Url));

			//AUTH
			if(Settings.Authentication.ScanAccountAllEvents){
				action |= ScanAccount(GetServerVariable(pfc,"LOGON_USER"));
			}

			//MONITOR - FILENAME
			if(Settings.Filename.Monitor.Enabled){
				if(IsInList(fn.FileNameLCase,Settings.Filename.Monitor.List)){
					logger.Append("MONITORED: File access: '" + fn.FileName + "'");
					LogClientInfoExtra(pfc);
					logger.Flush();
				}
			}

			//no more code here (logger.Flush())
		}			

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
				HackResponse(pfc);						//show page
			lock.Unlock();								//unlock globals
			if(logonly){								//if we are only here to log
				return CISAPIFilter::OnUrlMap(pfc, pUrlMap);
			}else{										//if we have to do more than logging
				/*  ISAPI Extension issues

					1) SF_STATUS_REQ_ERROR is needed for IIS 8 when our ISAPI extension is installed.
					Handler mapping already started in OnUrlMap, so we need	to block execution.
					This is not an issue on IIS 7 or when our ISAPI extension is not loaded on IIS 8.

					2) This also fixes the issue of the alert not being displayed in OnUrlMap on IIS 8
					when the ISAPI extension is loaded.

					3) SetLastError is needed when using Response Redirect, otherwise you will get an internal server error message

					4) Returning SF_STATUS_REQ_ERROR on W2K/XP and calling a folder, the default document mapping will generate an Internal Server Error.
				*/
				if(KnownIssues.UrlMap){
					SetLastError(ERROR_ACCESS_DENIED);//see http://blogs.msdn.com/b/david.wang/archive/2005/07/01/howto-isapi-filter-rejecting-requests-from-sf-notify-preproc-headers-based-on-http-referer.aspx
					pfc->ServerSupportFunction(pfc, SF_REQ_DISABLE_NOTIFICATIONS, NULL, SF_NOTIFY_URL_MAP, NULL); //needed for IIS 8 race condition which results in stack overflow
					return SF_STATUS_REQ_ERROR; //needed for IIS 8 to stop execution or multiple entries (IIS 7 & 8)
				}

				if(respdrop)
					return SF_STATUS_REQ_FINISHED;		//make sure IIS does nothing with request

				return SF_STATUS_REQ_FINISHED_KEEP_CONN;//make sure IIS does nothing with request
			}
		}else{
			//Admin/Stats page
			if(Settings.Admin.Enabled && Settings.IPRanges.Admin.IsInList(IP) && u.StartsWith(Settings.Admin.Url)){
				//we are in /WebKnight/ admin

				if(Settings.Admin.Login.GetLength()>0){
					CString pass = GetServerVariable(pfc,"HTTP_AUTHORIZATION");
					if(pass!="Basic " + CBase64::Encode(Settings.Admin.Login)){
						//wrong password, prompt for password

						//401 Unauthorized
						//WWW-Authenticate: basic
						CString authenticate("WWW-Authenticate: Basic");
						authenticate += CRLF; //needed!
						LPSTR lps = new char[authenticate.GetLength()+1];
						if(lps!=NULL){
							strcpy(lps, authenticate);
							pfc->AddResponseHeaders(pfc,lps,0);
							delete[] lps;
						}
						pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"401 Unauthorized",NULL,NULL);
						pfc->pFilterContext = CONTEXT_SENDING_REDIRECT;
						SendData(pfc,CString("<html><head><title>Not Authorized</title></head><body><h1>Not Authorized</h1><hr><p>HTTP Error 401. WebKnight admin requires user authentication.</p></body></html>"));

						logger.Cancel();
						lock.Unlock();
						return SF_STATUS_REQ_FINISHED_KEEP_CONN /* no SF_STATUS_REQ_ERROR here, we don't drop connection here */; //request handled
					}
				}

				//don't allow coming from another site (avoid CSRF!)
				CString ReferrerURL = GetServerVariable(pfc,"HTTP_REFERER");
				CString RefDomain = CURL::FQDNNoEndDot(ReferrerURL,false);
				CString HostHeader = GetServerVariable(pfc,"HTTP_HOST");
				if(ReferrerURL.GetLength()==0 || RefDomain.CompareNoCase(HostHeader)==0 ){
					
					if(u.Url == Settings.Admin.Url){
						//root = built-in functionality
						RunAdmin(pfc,Settings.Admin.dll);
						logger.Cancel();
						lock.Unlock();

						if(KnownIssues.UrlMap){
							SetLastError(ERROR_ACCESS_DENIED);
							pfc->ServerSupportFunction(pfc, SF_REQ_DISABLE_NOTIFICATIONS, NULL, SF_NOTIFY_URL_MAP, NULL);
							return SF_STATUS_REQ_ERROR; //for Windows 10 - connection reset message in browser
						}else{
							return SF_STATUS_REQ_FINISHED_KEEP_CONN /* no SF_STATUS_REQ_ERROR here, we don't drop connection here */; //request handled
						}

					}else if(Settings.Admin.AllowConfigChanges){
						//ASP pages in WebKnight folder if changes are allowed
						CString script = GetServerVariable(pfc,"SCRIPT_NAME");
						script.Replace(Settings.Admin.Url,"");
						script.Replace('/','\\');
						script = Settings.Admin.dll.Path + script;
						strcpy(pUrlMap->pszPhysicalPath, script.GetBuffer(0));

						//skip scanning (information disclosure - havij string detection is seen as american express)
						pfc->ServerSupportFunction(pfc,SF_REQ_DISABLE_NOTIFICATIONS,NULL,SF_NOTIFY_SEND_RAW_DATA,NULL);
					}
				}
			}

			//allowed request
			if((action.Status[Action::Monitor] || Settings.Logging.LogAllowed) && logger.HasEntry()){//do not log allowed requests if asked
				logger.Append("ALLOWED");
				logger.Flush();
			}else{
				logger.Cancel();						//clear the log entry
			}
			lock.Unlock();								//unlock globals
			return CISAPIFilter::OnUrlMap(pfc, pUrlMap);
		}
	}
	return CISAPIFilter::OnUrlMap(pfc, pUrlMap);

#ifdef ERROR_HANDLE
	}catch(...){
		if(DENY_ON_ERROR){							//deny request on error if asked
			if(KnownIssues.UrlMap){
				SetLastError(ERROR_ACCESS_DENIED);
				pfc->ServerSupportFunction(pfc, SF_REQ_DISABLE_NOTIFICATIONS, NULL, SF_NOTIFY_URL_MAP, NULL); //needed for IIS 8 race condition which results in stack overflow
				return SF_STATUS_REQ_ERROR;			// needed for IIS 8 to stop execution
			}else
				return SF_STATUS_REQ_FINISHED;		//don't keep connection, because of error
		}else{
			return CISAPIFilter::OnUrlMap(pfc, pUrlMap);
		}
	}
#endif
}

DWORD CISAPIFirewall::OnSendResponse(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE pResponse)
{
#ifdef ERROR_HANDLE
	try{
#endif

	if(pfc!=NULL && pResponse!=NULL){
		
		bool doflush(false);
		CString instance = GetServerVariable(pfc,"INSTANCE_ID");

		CSingleLock lock(&Settings.crit, TRUE);

		if (instance.GetLength()==0){
			logger.NewEntry("GLOBAL");
		}else{
			logger.NewEntry(SITEINSTANCE + instance);
		}
		logger.Append("OnSendResponse");
		LogClientInfo(pfc);
		LogRequestLine(pfc);

		//Fix for response headers and image in one chunk -> no headers were adjusted in OnSendRawData
		CString IP(GetClientIP(pfc));
		if(!IsExcludedSite(instance) && !IsExcludedIP(IP)){
			//status
			//CString Status = Safe_DWORDToAscii(pResponse->HttpStatus);
			//doflush |= ScanResponseStatus(pfc,Status,reset,logext,IP); //done in OnSendRawData

			//change response headers
			if(Settings.ResponseMonitor.Headers.Enabled){
				if(!ChangeHeader(pfc,pResponse,Settings.ResponseMonitor.Headers.Map))
					doflush = true;
			}

			//COOKIE: HttpOnly and Secure attribute
			if(Settings.Cookie.HttpOnly || Settings.Cookie.Secure){
				//WARNING: Secure/HttpOnly attribute not working when there are 2 or more Set-Cookie headers
				//Is by design (GetHeader concats multiple Set-Cookie headers), we won't fix it in ISAPI
				//TODO: MODULE - change multiple Set-Cookie headers
				CString cookie = GetHeader(pfc, pResponse,"Set-Cookie:");
				if(cookie.GetLength()>0){
					bool needChange = false;
					if(Settings.Cookie.HttpOnly && cookie.Find("; HttpOnly")<1){
						cookie += "; HttpOnly";
						needChange = true;
					}
					if(Settings.Cookie.Secure && GetServerVariable(pfc,"HTTPS")=="on" && cookie.Find("; Secure")<1){
						cookie += "; Secure";
						needChange = true;
					}
					if(needChange){
						pResponse->SetHeader(pfc,"Set-Cookie:",cookie.GetBuffer(0));
					}
				}
			}
		}

		if(KnownIssues.SkipSendRawData && (IsIIS7ProblemResponse(pfc,pResponse) || (IsWebsocketsUpgrade(pfc,pResponse)) )){
			//Fix for IIS 7 PDF + ZIP > 256MiB issue
			pfc->pFilterContext = CONTEXT_SENDING_DATA;
			//disable OnSendRawData
			pfc->ServerSupportFunction(pfc,SF_REQ_DISABLE_NOTIFICATIONS,NULL,SF_NOTIFY_SEND_RAW_DATA,NULL);
			logger.Append("Disabled OnSendRawData for this request");
		}

		//flush or cancel log entry
		if (doflush){
			logger.Flush();
		}else{
			logger.Cancel();
		}

		lock.Unlock();
	}
	return CISAPIFilter::OnSendResponse(pfc, pResponse);

#ifdef ERROR_HANDLE
	}catch(...){
		//do nothing, some error occured removing/changing server header, but allow request
		return CISAPIFilter::OnSendResponse(pfc, pResponse);
	}
#endif
}


DWORD CISAPIFirewall::OnSendRawData(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pRawData)
{
	/*
	 * Inspect the response from the server.
	 */ 
#ifdef ERROR_HANDLE
	try{
#endif

	if(pfc!=NULL && pRawData!=NULL){
		
		if(pfc->pFilterContext!=CONTEXT_SENDING_DATA && pfc->pFilterContext!=CONTEXT_SENDING_ALERT){	//only if headers are not sent back: not good with bad requests (stays NULL)

			Action action;
			bool doflush(false);
			bool resetContext(true);
			bool isNewResponse(false);
			CString instance = GetServerVariable(pfc,"INSTANCE_ID");

			CSingleLock lock(&Settings.crit, TRUE);

			bool logonly(Settings.Response.LogOnly);

			if (instance.GetLength()==0){
				logger.NewEntry("GLOBAL");
			}else{
				logger.NewEntry(SITEINSTANCE + instance);
			}
			logger.Append("OnSendRawData");
			LogClientInfo(pfc);
			LogRequestLine(pfc);

			CString IP(GetClientIP(pfc));
			if(!IsExcludedSite(instance) && !IsExcludedIP(IP)){
				//only if we did not already process this request and this is just additional data
				//if(pfc->pFilterContext != CONTEXT_SENDINGDATA){ //this did not work!!! (with HTTP 100 Continue response,
				//next response from server: no server header changed/removed)
				
				//prepare the raw data before processing	
				CString resp("");
				bool doCustomScan(true);
				bool doIntercept = (Intercept.IP.GetLength()>0 && IP==Intercept.IP);
				if(!ConvertBinaryData((BYTE*)pRawData->pvInData,pRawData->cbInData,resp)){
					#ifdef LOG_DEBUG_ONSENDRAWDATA
					logger.Append("Could not convert binary data to string (NULL characters present)");
					doflush = true;
					#endif
					resp = CString((char*)pRawData->pvInData);	//to first NULL
					doCustomScan = false;
				}

				#ifdef LOG_DEBUG_ONSENDRAWDATA
				logger.Append("\r\nRaw data:");
				logger.Append(resp);
				doflush = true;
				#endif

				//start of a http response
				if(resp.Left(5)=="HTTP/"){
					int pos;
					isNewResponse = true;

					//status
					CString status("");
					pos = resp.Find(CRLF);
					status = resp.Left(pos==-1?resp.GetLength():pos);
					pos = status.Find(' ');
					if(pos!=-1 && pos<status.GetLength()-3){
						status = status.Mid(pos+1);

						bool logext(false);
						if(ScanResponseStatus(pfc,status,resetContext,logext,IP)){
							logger.AppendEscape(resp.Left(1024));
							doflush = true;
							if(logext){ //server error
								//log all subsequent writes until another request is received
								resetContext = false;
								pfc->pFilterContext = CONTEXT_SENDING_LOG;
							}
						}
					}

					if(doCustomScan){//if not embedded NULL
						
						if(Settings.ResponseMonitor.InformationDisclosure.Action || doIntercept){
							CMIME mime(CMIME::GetHeader(resp,"Content-Type:","ignore"));
							if(mime.IsText){
								//scan subsequent writes as well
								resetContext = false;
								pfc->pFilterContext = CONTEXT_SENDING_TEXT;

								//intercept request
								if(doIntercept){
									Intercept.Page = "<html><head><title>Intercepted Message</title><base href=\"" + CHTML::Encode(GetServerVariable(pfc,"URL")) + "\"></head><body><div style=\"color:black;background-color:white;\">Message intercepted from " + Intercept.IP + " (<a href=\"" + Settings.Admin.Url + "?Intercept=Reset\">reset</a>) on " + CTime::GetCurrentTime().FormatGmt("%Y-%m-%d %H:%M:%S GMT") + "<br/><pre>" + CHTML::Encode(SerializeRequest(pfc)) + "</pre><hr></div>";
								}
							}
						}
					}
				}else{
					if(pfc->pFilterContext==CONTEXT_SENDING_LOG){
						//ASP.NET errors (in separate data write after headers)
						logger.AppendEscape(resp.Left(8192));
						doflush = true;
					}
				}

				if(pfc->pFilterContext == CONTEXT_SENDING_TEXT){
					resetContext = false; //scan next writes also

					//information disclosure
					if(Settings.ResponseMonitor.InformationDisclosure.Action){
						if(DenyRegex(resp,Settings.ResponseMonitor.InformationDisclosure.Map,"'","' information disclosure",Settings.ResponseMonitor.InformationDisclosure.Action)){
							action.Set(Settings.ResponseMonitor.InformationDisclosure.Action);
						}
					}
					//intercept response
					if(doIntercept){
						if(isNewResponse)
							Intercept.Page += CWebAdmin::AddPreformatted(CHTML::Encode(resp)); //headers
						else
							Intercept.Page += resp;	//body
					}
				}
			}

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
				if(!logonly){								//if we have to do more than logging
					pRawData->cbInData = 0;					//clear current response
					HackResponse(pfc,true,isNewResponse);	//show page
				}
				lock.Unlock();								//unlock globals
				if(logonly){								//if we are only here to log
					return CISAPIFilter::OnSendRawData(pfc, pRawData);
				}else{										//if we have to do more than logging
					//return SF_STATUS_REQ_FINISHED;		//not working on W2K/XP (response is seen and then 500 internal server error occurs)
					SetLastError(ERROR_ACCESS_DENIED);
					return SF_STATUS_REQ_ERROR;				//make sure IIS does nothing with request
				}
			}else{
				//reset context
				if(resetContext){
					pfc->pFilterContext = CONTEXT_SENDING_DATA;
					//disable further notifications for this request (performance gain)
					pfc->ServerSupportFunction(pfc,SF_REQ_DISABLE_NOTIFICATIONS,NULL,SF_NOTIFY_SEND_RAW_DATA,NULL);
				}
				if((action.Status[Action::Monitor] || Settings.Logging.LogAllowed) && logger.HasEntry()){//do not log allowed requests if asked
					logger.Append("ALLOWED");
					doflush = true;
				}
				//flush or cancel log entry
				if (doflush){
					logger.Flush();
				}else{
					logger.Cancel();
				}

				lock.Unlock();
			}
		}
	}
	return CISAPIFilter::OnSendRawData(pfc, pRawData);

#ifdef ERROR_HANDLE
	}catch(...){
		//do nothing, some error occured removing/changing server header, but allow request
		return CISAPIFilter::OnSendRawData(pfc, pRawData);
	}
#endif
}

DWORD CISAPIFirewall::OnLog(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_LOG pLog)
{
#ifdef ERROR_HANDLE
	try{
#endif

	if(pfc!=NULL && pLog!=NULL){

		//WARNING: pLog is a WPX_FILTER_LOG in Forefront TMG (support for files larger than 4GB)

		//if blocked directly, set status code in IIS log
		//In TMG the log will say: Failed Connection Attempt (Status: 12210 An Internet Server API (ISAPI) filter has finished handling the request. Contact your system administrator)
		if(pfc->pFilterContext == CONTEXT_SENDING_ALERT){
			pLog->dwHttpStatus = Settings.HTTPResponse.StatusCode;
			pfc->pFilterContext = CONTEXT_NEW_REQUEST; //reset for OnReadRawData
		}

		//change logged c-ip to IP variable (like X-Forwarded-For)
		if(Settings.Connection.ChangeLogIPVariable){
			//pLog->pszClientHostName = GetClientIP(pfc); //according to MSDN this is not safe (although it seems to work)
			//pfc->pFilterContext = pfc->AllocMem(pfc,ip.GetLength,0); //don't use AllocMem -> DoS possible if connection is kept open and lots of requests
			CString* ip = new CString(GetClientIP(pfc));
			pfc->pFilterContext = ip; //heap allocation, but cleanup in OnReadRawData/OnPreprocHeaders
			pLog->pszClientHostName = (CHAR*)ip->GetBuffer(0);
		}

	}
	return SF_STATUS_REQ_NEXT_NOTIFICATION;

#ifdef ERROR_HANDLE
	}catch(...){
		//do nothing
		return CISAPIFilter::OnLog(pfc, pLog);
	}
#endif
}

DWORD CISAPIFirewall::OnEndOfNetSession(PHTTP_FILTER_CONTEXT pfc)
{
#ifdef ERROR_HANDLE
	try{
#endif

	//cleanup heap allocation from OnLog event
	if(pfc!=NULL && pfc->pFilterContext!=NULL && pfc->pFilterContext>CONTEXT_MAX){
		delete (CString*)pfc->pFilterContext;
		pfc->pFilterContext = NULL;
	}
	return SF_STATUS_REQ_NEXT_NOTIFICATION;

#ifdef ERROR_HANDLE
	}catch(...){
		//do nothing
		return CISAPIFilter::OnEndOfNetSession(pfc);
	}
#endif
}

void CISAPIFirewall::HackResponse(PHTTP_FILTER_CONTEXT pfc, bool SendMessageBody, bool SendHeaders)
{
	if(Settings.HTTPResponse.Directly){
		pfc->pFilterContext = CONTEXT_SENDING_ALERT;	//otherwise "Server" header is changed again
		//direct response to client (writeclient)
		CString buf = GetAlertResponse(SendMessageBody,SendHeaders);
		DWORD szbuf(buf.GetLength());
		pfc->WriteClient(pfc, buf.GetBuffer(0),&szbuf, 0);
	}else if(Settings.HTTPResponse.Redirect){
		//BUGFIX IIS 7/8 when alert is triggered in (OnPreprocHeaders and OnUrlMap) OR (twice OnUrlMap e.g. due to ISAPI extension)
		//for the same request, you would get 2x Location header (tested with "/scripts" folder on IIS 7)
		if(pfc->pFilterContext != CONTEXT_SENDING_REDIRECT){
			//redirect request to a url
			CString location("Location: " + Settings.HTTPResponse.RedirectURL + CRLF);
			LPSTR lps = new char[location.GetLength()+1];
			if(lps!=NULL){
				strcpy(lps, location);
				pfc->AddResponseHeaders(pfc,lps,0);	//no longer using MFC ISAPI 
				delete[] lps;
			}
			pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"302 Object Moved",NULL,NULL);
			pfc->pFilterContext = CONTEXT_SENDING_REDIRECT;
		}
	}else if(Settings.HTTPResponse.UseStatus){
		//respond with special header only
		pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,(LPVOID)(LPCTSTR)Settings.HTTPResponse.Status,NULL,NULL);
		pfc->pFilterContext = CONTEXT_NEW_REQUEST; //reset for OnReadRawData
	}
}

void CISAPIFirewall::SendPage(PHTTP_FILTER_CONTEXT pfc, CString& Text, bool SendMessageBody, LPCTSTR ContentType)
{
	pfc->pFilterContext = CONTEXT_SENDING_DATA;	//otherwise "Server" header is changed again
	//direct response to client (writeclient)
	CString buf("HTTP/1.1 200 OK");
	buf += "\r\nServer: "; buf += Settings.Admin.ServerHeader;

	buf += "\r\nX-Frame-Options: DENY";
	buf += "\r\nX-Content-Type-Options: nosniff";
	buf += "\r\nX-XSS-Protection: 1; mode=block";

	_tzset();
	CString d = CTime::GetCurrentTime().FormatGmt("%a, %d %b %Y %H:%M:%S GMT");
	buf += "\r\nDate: " + d;
	buf += "\r\nContent-Type: "; buf += ContentType;
	buf += "\r\nContent-Length: "; buf += CStringHelper::Safe_IntToAscii(Text.GetLength());
	buf += "\r\nPragma: no-cache";
	buf += "\r\nCache-control: no-cache";
	buf += "\r\nExpires: " + d;
	buf += CRLFCRLF;
	if(SendMessageBody){ //see e-mail: special feature request of Sanford Whiteman if HEAD request -> no message body
		buf += Text;
	}
	SendData(pfc,buf);
}

bool CISAPIFirewall::SendFile(PHTTP_FILTER_CONTEXT pfc, CString& Path, bool SendMessageBody, LPCTSTR ContentType, unsigned int MaxSize)
{
	CString Contents;
	if(CFileName::ReadFileToString(Path,Contents,MaxSize)){
		SendPage(pfc,Contents,SendMessageBody,ContentType);
		return true;
	}else{
		return false;
	}
}

inline void CISAPIFirewall::LogClientInfo(PHTTP_FILTER_CONTEXT pfc)
{
	if(Settings.Logging.LogClientIP) logger.Append(GetClientIP(pfc));
	if(Settings.Logging.LogUserName) logger.Append(GetServerVariable(pfc,"LOGON_USER"));
	if(Settings.HTTPLogging.Log_HTTP_VIA) logger.Append(GetServerVariable(pfc,"HTTP_VIA"));
	if(Settings.HTTPLogging.Log_HTTP_X_FORWARDED_FOR) logger.Append(GetServerVariable(pfc,"HTTP_X_FORWARDED_FOR"));
	if(Settings.HTTPLogging.LogHostHeader) logger.Append(GetServerVariable(pfc,"HTTP_HOST"));
	if(Settings.HTTPLogging.LogUserAgent) logger.Append(GetServerVariable(pfc,"HTTP_USER_AGENT"));
}

inline void CISAPIFirewall::LogClientInfoExtra(PHTTP_FILTER_CONTEXT pfc)
{
	logger.Append("Referer: '" + GetServerVariable(pfc,"HTTP_REFERER") + "'");
	logger.Append("User-Agent: '" + GetServerVariable(pfc,"HTTP_USER_AGENT") + "'");
	logger.Append("From: '" + GetServerVariable(pfc,"HTTP_FROM") + "'");
	logger.Append("Accept-Language: '" + GetServerVariable(pfc, "HTTP_ACCEPT_LANGUAGE") + "'");
	logger.Append("Accept: '" + GetServerVariable(pfc, "HTTP_ACCEPT") + "'");
}

inline void CISAPIFirewall::LogRequestLine(PHTTP_FILTER_CONTEXT pfc)
{
	logger.Append(GetServerVariable(pfc,"REQUEST_METHOD"));
	logger.Append(GetServerVariable(pfc,"SCRIPT_NAME"));
	logger.Append(GetServerVariable(pfc,"PATH_INFO"));
	logger.Append(GetServerVariable(pfc,"QUERY_STRING"));
}

void CISAPIFirewall::LogRequest(PHTTP_FILTER_CONTEXT pfc)
{
	CString& request = SerializeRequest(pfc);
	logger.AppendEscape(request);
}

bool CISAPIFirewall::ScanResponseStatus(PHTTP_FILTER_CONTEXT pfc, LPCTSTR Status,bool& ResetFilterContext, bool& IsServerError, CString IP)
{
	if(Status!=NULL){
		switch(Status[0]){
		case '1':
			//if this is not a class 1 response (100 Continue,101), reset filtercontext pointer
			//otherwise with a simple refresh in browser one might circumvent header checking (filtercontext = void* 1)
			//because filtercontext = per connection (with keep-alives -> same filtercontext)
			ResetFilterContext=false;
			return false;
			break;
		case '4':
			if(Settings.ResponseMonitor.ClientErrors.Action){
				Statistics.IP_RESPONSE_Client_Errors.Add(IP,GetServerVariable(pfc,"SCRIPT_NAME"));
			}
			if(Settings.ResponseMonitor.LogClientErrors){
				logger.Append("HTTP Client Error");
				logger.Append(Status);
				//LogRequestLine(pfc);
				LogClientInfoExtra(pfc);
				return true;
			}
			break;
		case '5':
			if(Settings.ResponseMonitor.ServerErrors.Action){
				Statistics.IP_RESPONSE_Server_Errors.Add(IP,GetServerVariable(pfc,"SCRIPT_NAME"));
			}
			if(Settings.ResponseMonitor.LogServerErrors){
				logger.Append("HTTP Server Error");
				logger.Append(Status);
				//LogRequestLine(pfc);
				LogClientInfoExtra(pfc);
				IsServerError=true; //also log subsequent data sending
				return true;
			}
			break;
		}
	}
	return false;
}
#define SF_NOTIFY_FLAG_LARGE_SIZE_AWARE 0x00100000

void CISAPIFirewall::SetFilterVersion(PHTTP_FILTER_VERSION pVer)
{
	Message("INFO: ISAPI server version: " + Safe_LongToAscii(HIWORD(pVer->dwServerFilterVersion)) + "." + Safe_LongToAscii(LOWORD(pVer->dwServerFilterVersion)));
	//Message("INFO: ISAPI client version: " + Safe_LongToAscii(HIWORD(pVer->dwFilterVersion)) + "." + Safe_LongToAscii(LOWORD(pVer->dwFilterVersion)));
	Message("INFO: Firewall is running as user '" + CProcessHelper::GetCurrentUserName() + "' and loaded in process: " + CProcessHelper::GetProcessPath());

#ifdef ENABLE_ODBC
	if(Settings.Logging.ODBCEnabled){
		CString error = logger.ODBC.GetError();
		if(error!=""){
			logger.UseODBC = false;
			Message("WARNING: ODBC disabled, " + error);
		}
	}
#endif
	//if ( pVer->dwServerFilterVersion >= MAKELONG( 0, 6 ) )
	//{
	//// The server is IIS6 and later - should not use SF_NOTIFY_READ_RAW_DATA
	//}
	
	//ISAPI versions
	//4.0: IIS 5.1 (Windows XP) "C:\WINDOWS\system32\inetsrv\inetinfo.exe"
	//6.0: ISA 2004 "C:\Program Files\Microsoft ISA Server\wspsrv.exe"
	//7.0:
	//7.5: IIS 7.5 (Windows 2008 R2) "c:\windows\system32\inetsrv\w3wp.exe"
	//8.0: ForeFront TMG 2010 "C:\Program Files\Microsoft Forefront Threat Management Gateway\wspsrv.exe"
	//GetWPXFilterVersion + HttpWPXFilterVersion -> new in ISA Server 2004 & 2006

	// Set the filter priority
	if(Settings.Engine.AllowLateScanning){
		pVer->dwFlags |= SF_NOTIFY_ORDER_LOW;
		Message("WARNING: Firewall is installed as low priority (possible risk)");
	}else{
		pVer->dwFlags |= SF_NOTIFY_ORDER_HIGH;
		Message("INFO: Firewall is installed as high priority (very secure)");
	}
	
	//always register for these events
	pVer->dwFlags |= SF_NOTIFY_PREPROC_HEADERS;
	
	if(Settings.Authentication.NotifyAuthentication)
		pVer->dwFlags |= SF_NOTIFY_AUTHENTICATION;

	//for IIS 6/7... HTTP status code in IIS log when response directly (IIS 5 does not log anything if blocked before OnSendRawData)
	pVer->dwFlags |= SF_NOTIFY_LOG | SF_NOTIFY_END_OF_NET_SESSION;

	//are we a global filter? if yes, we can use the OnReadRawData event
#ifdef DO_READRAWDATA_EVENT
	if(Settings.Global.IsInstalledInWebProxy){
		//In ISA/TMG
		if(pVer->dwServerFilterVersion >= MAKELONG( 0, 7 )){
			//Forefront TMG warning about 4GB limit
			pVer->dwFlags |= SF_NOTIFY_FLAG_LARGE_SIZE_AWARE;
		}
		if(Settings.Global.IsInstalledAsGlobalFilter){
			//process raw data if asked
			pVer->dwFlags |= SF_NOTIFY_READ_RAW_DATA;
			Message("INFO: Firewall will process raw data because it is a global ISAPI filter (OnReadRawData event)");
		}else{
			Message("WARNING: ISAPI Filter will not process raw data because it is not a global filter (no OnReadRawData event, all other capabilities of the firewall will still be used)");
			Message("INFO: If you want to use the additional raw data scanning capabilities of the firewall, make sure the 'Is Installed As Global Filter' under Global Filter Capabilities is checked (needs a restart)");	
		}
	}else{
		//IIS
		if(pVer->dwServerFilterVersion >= MAKELONG( 0, 7 )){
			//no OnReadRawData in IIS7 and later
			Message("INFO: ISAPI Filter will not process raw data because this ISAPI version does not support it (OnReadRawData event is not supported in IIS7 and later).");
			Message("INFO: WebKnight has a pass-through wildcard ISAPI extension for scanning POST data which is by default installed on IIS 7 and later. You'll see this extension in action in the event OnPassThrough.");
		}else{
			//IIS 5/6(in IIS5 isolation mode)
			if(Settings.Global.IsInstalledAsGlobalFilter){
				pVer->dwFlags |= SF_NOTIFY_READ_RAW_DATA;
				Message("INFO: Firewall will process raw data because it is a global ISAPI filter (OnReadRawData event)");
				Message("WARNING: If the firewall fails to load (red arrow down), make sure it is installed as a global filter or uncheck 'Is Installed As Global Filter' in Global Filter Capabilities (needs a restart)");
			}else{
				Message("WARNING: ISAPI Filter will not process raw data because it is not a global filter (no OnReadRawData event, all other capabilities of the firewall will still be used)");
				Message("INFO: If you want to use the additional raw data scanning capabilities of the firewall, you need to install it as a global filter (needs IIS 5 Isolation) and make sure the 'Is Installed As Global Filter' under Global Filter Capabilities is checked (needs a restart)");
				Message("INFO: WebKnight has a pass-through wildcard ISAPI extension for scanning POST data. Just add WebKnight.dll as a wildcard ISAPI Extension in your application mappings (not supported in IIS 5).");
			}
		}
	}
#endif
	
	//do we need to scan non-secure port?
	if(Settings.Engine.ScanNonSecurePort){
		pVer->dwFlags |= SF_NOTIFY_NONSECURE_PORT;
		Message("INFO: HTTP traffic will be monitored");
	}else{
		Message("WARNING: HTTP traffic will NOT be monitored");
	}
	
	//do we need to scan secure port?
	if(Settings.Engine.ScanSecurePort){
		pVer->dwFlags |= SF_NOTIFY_SECURE_PORT;
		Message("INFO: HTTPS traffic will be monitored");
	}else{
		Message("WARNING: HTTPS traffic will NOT be monitored");
	}

	//ignore OnUrlMap in ISA/TMG
	if(Settings.Global.IsInstalledInWebProxy){
		KnownIssues.UrlMap = false;
	}else{
		pVer->dwFlags |= SF_NOTIFY_URL_MAP;

		//IIS 7/8 OnUrlMap issue
		KnownIssues.UrlMap = pVer->dwServerFilterVersion >= MAKELONG( 0, 7 );
	}

	//for changing response headers (IIS 5/6/7+)
	//change headers in OnSendResponse (BUG IIS6/7 headers and image in one chunk, no headers were adjusted)
	if(Settings.ResponseMonitor.Headers.Enabled || Settings.Cookie.HttpOnly || Settings.Cookie.Secure)
		pVer->dwFlags |= SF_NOTIFY_SEND_RESPONSE;

	//scan responses
	if(Settings.ResponseMonitor.IsNeeded()){
		pVer->dwFlags |= SF_NOTIFY_SEND_RAW_DATA;
			
		if(pVer->dwServerFilterVersion >= MAKELONG( 0, 7 )){
			//no OnSendRawData in IIS 7.5 for >256MB file download bug
			KnownIssues.SkipSendRawData = true;
		}
	}
}

bool CISAPIFirewall::OnReadRawDataDebug(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pRawData)
{
	try{

		logger.NewEntry("GLOBAL");
		logger.Append("OnReadRawDataDebug");
		LogClientInfo(pfc);
		logger.Append("pRawData->cbInBuffer");
		logger.Append((int)pRawData->cbInBuffer);
		logger.Append("pRawData->cbInData");
		logger.Append((int)pRawData->cbInData);
		logger.Append("pFilterContext");
		logger.Append((int)pfc->pFilterContext);
		logger.Flush();
		return true;

	}catch(...){
		return false;
	}
}

Action CISAPIFirewall::ScanHeaders(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders)
{
	Action action;
	POSITION pos;
	CString str;

	//HEADERS: Deny certain headers (list is case insensitive by RFC - GetHeader does this for us)
	if(Settings.Headers.DenyHeaders.Action){
		pos = Settings.Headers.DenyHeaders.List.GetHeadPosition();
		while (pos != NULL){
			str=Settings.Headers.DenyHeaders.List.GetNext(pos);
			CString h = GetHeader(pfc,pHeaders,str.GetBuffer(0));
			if(h!=""){
				action.Set(Settings.Headers.DenyHeaders.Action);
				Alert("Header '" + str + "' not allowed",Settings.Headers.DenyHeaders.Action);
				logger.Append(h.Left(1024));
			}
		}
	}

	//HEADERS: Check length of certain headers
	if(Settings.Headers.MaxHeaders.Action){
		pos = Settings.Headers.MaxHeaders.Map.GetStartPosition();
		CString hsize; CString h;
		while(pos!=NULL){
			Settings.Headers.MaxHeaders.Map.GetNextAssoc(pos, h, hsize);
			str = GetHeader(pfc,pHeaders,h.GetBuffer(0));
			if(str.GetLength()>atol(hsize)){
				action.Set(Settings.Headers.MaxHeaders.Action);
				Alert("Header '" + h + "' too long",Settings.Headers.MaxHeaders.Action);
				logger.Append(str.Left(1024));
			}
		}
	}

	return action;
}

Action CISAPIFirewall::CustomHeaderScanning(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders, CString& ip, CURL& RawUrl, CString& ua, CString& version)
{
	logger.AppendEscape(ua.Left(2048));

	if(version.GetLength()==0 || version=="HTTP/0.9")
		return Action();

	//HEADERS: User Agent
	return ScanUserAgent(ua,ip);
}

CString CISAPIFirewall::GetClientIP(PHTTP_FILTER_CONTEXT pfc)
{
	CString IP("");
	//get custom header like X-Forwarded-For
	if(Settings.Connection.ClientIPVariable.GetLength()>0){
		IP = GetServerVariable(pfc,Settings.Connection.ClientIPVariable.GetBuffer(0));
		//if multiple X-Forwarded-For headers are present, only use the last one, others can be spoofed
		int pos = IP.ReverseFind(',');
		if(pos>-1 && pos<IP.GetLength()){
			IP = IP.Mid(pos+1,IP.GetLength()-pos-1).Trim();
		}
	}
	//get standard header if custom header is not present
	if(IP == ""){
		IP = GetServerVariable(pfc,REMOTE_ADDR);
	}
	return IP;
}

void CISAPIFirewall::RunAdmin(PHTTP_FILTER_CONTEXT pfc, CFileName dll /* not byref! */)
{
	CString Message("&nbsp;");
	bool done(false);
	bool IsHEADRequest = (GetServerVariable(pfc,"REQUEST_METHOD")=="HEAD");

	CString qs = GetServerVariable(pfc,"QUERY_STRING");
	CString Action = qs;
	int pos = Action.FindOneOf("&="); //first word is action, rest is parameters
	if(pos>-1){
		Action = Action.Left(pos);
	}
	CString subaction = CWebAdmin::GetQueryStringValue(qs,Action);

	//default
	if(Action == "")
		Action = "Home";

	//Home
	if(Action=="Home")
	{ 
		Message = "<a href=\"?Home\">Firewall</a> - <a href=\"?Home=IPRanges\">IP Ranges</a> - <a href=\"?Home=Statistics\">Statistics</a>";
		if(Settings.Admin.AllowConfigChanges)
			Message += " - <a href=\"?Home=ClearCache\">Reset statistics</a> - <a href=\"?Home=ClearIP\">Unblock IP</a>";

		if(subaction==""){
			//do nothing, show dashboard (see below)
		}else if(subaction=="Statistics" || ((subaction=="ClearCache" || subaction=="ClearIP") && Settings.Admin.AllowConfigChanges)){
			CString body("");
			if(subaction=="ClearCache")
				ClearCache();
			if(subaction=="ClearIP"){
				CString IP = CWebAdmin::GetQueryStringValue(qs,"IP");
				if(IP=="")
					Message = "Enter an IP address to unblock: <form method=\"GET\" action=\"?\"><input type=\"hidden\" name=\"Home\" value=\"ClearIP\"><input type=text name=\"IP\" value=\"\"><input type=\"submit\" name=\"submit\" value=\"Submit\"></form>";
				else
					Statistics.ClearIP(IP);
			}
			body += CWebAdmin::BuildMenu(Message);
			body += BuildStatistics();
			SendPage(pfc,CWebAdmin::BuildPage(Settings.Admin.ServerHeader,body),!IsHEADRequest);
			done = true;
		}else if(subaction=="ClearIP" && Settings.Admin.AllowConfigChanges){

		}else if(subaction=="IPRanges"){
			CString body("");
			body += CWebAdmin::BuildMenu(Message);
			body += BuildIPRanges();
			SendPage(pfc,CWebAdmin::BuildPage(Settings.Admin.ServerHeader,body),!IsHEADRequest);
			done = true;
		}

	}

	//Settings
	else if(Action=="Settings"){
		if(subaction=="" || subaction=="Dashboard"){
			if(Settings.Admin.AllowConfigChanges){ //also needs to have IUSR access
				CFileName fnConfig = Settings.FileStamp.FileName;
				CFileName fnLoaded = Settings.GetLoadedSettingsFileName();
				Message = "<a href=\"default.asp?file=" + CHTML::Encode(fnConfig.FileName) + "\">Configured settings</a> - <a href=\"default.asp?file=" + CHTML::Encode(fnLoaded.FileName) + "\">Loaded settings</a> - <a href=\"?Settings=Update\">Reload settings</a>";
			}else{
				Message = "<a href=\"?Settings=Configured\">Configured settings</a> - <a href=\"?Settings=Loaded\">Loaded settings</a>";
			}

		}else if(subaction=="Configured"){
			//view settings as xml with xslt file
			done = ShowSettingsFile(pfc,Settings.FileStamp.FileName,!IsHEADRequest);
			Message = "Error reading file: " + CHTML::Encode(Settings.FileStamp.FileName);
	
		}else if(subaction=="Loaded"){
			//view settings as xml with xslt file
			done = ShowSettingsFile(pfc,Settings.GetLoadedSettingsFileName(),!IsHEADRequest);
			Message = "Error reading file: " + CHTML::Encode(Settings.GetLoadedSettingsFileName());

		}else if(subaction=="Robots"){
			//view settings as xml with xslt file
			done = ShowSettingsFile(pfc,Settings.Agents.AgentList.FileStamp.FileName,!IsHEADRequest);
			Message = "Error reading file: " + CHTML::Encode(Settings.Agents.AgentList.FileStamp.FileName);

		}else if(subaction=="Headers"){
			//view settings as xml with xslt file
			done = ShowSettingsFile(pfc,Settings.Headers.Validation.FileStamp.FileName,!IsHEADRequest);
			Message = "Error reading file: " + CHTML::Encode(Settings.Headers.Validation.FileStamp.FileName);

		}else if(subaction=="Parameters"){
			//view settings as xml with xslt file
			done = ShowSettingsFile(pfc,Settings.ApplicationParameters.FileStamp.FileName,!IsHEADRequest);
			Message = "Error reading file: " + CHTML::Encode(Settings.ApplicationParameters.FileStamp.FileName);

		//Update Settings
		}else if(subaction=="Update" && Settings.Admin.AllowConfigChanges){
			logger.Cancel();
			if(UpdateSettings(true))
				Message = "Settings reloaded from: " + CHTML::Encode(Settings.FileStamp.FileName);
		}

	}
	else if(Action=="GUIXSL")
	{
		done = SendFile(pfc, dll.Path + "GUI.xsl",!IsHEADRequest,"text/xml");
		Message = "Error reading file: " + CHTML::Encode(dll.Path) + "GUI.xsl";
	}

	//Log
	else if(Action=="Log")
	{
		if(Settings.Logging.Enabled){

			if(subaction=="JSON"){
				//ADMIN - List/Details view in javascript - W2UI XSS injection, so look for better component
				//done = SendFile(pfc,CString(Settings.Admin.dll.Path + "LogFiles\\Export.json"),!IsHEADRequest,"text/plain",50000000);
				//Message = "Error reading JSON file";
			}else{
				//send current log file as text/plain
				done = SendFile(pfc,logger.CurrentLog.GetFileName(),!IsHEADRequest,"text/plain",50000000);
				Message = "Error reading file: " + CHTML::Encode(logger.CurrentLog.GetFileName());
			}
		}else{
			Message = "Logging is disabled";
		}

	}
	//Robots
	else if(Action=="Robots")
	{
		if(subaction=="" || subaction=="Dashboard"){
			if(Settings.Admin.AllowConfigChanges){
				CFileName fnRobots = Settings.Agents.AgentList.FileStamp.FileName;
				Message = "";
				if(fnRobots.FileName.GetLength()>0)
					Message = "<a href=\"default.asp?file=" + CHTML::Encode(fnRobots.FileName) + "\">Robots database</a> - ";
				Message += "<a href=\"default.asp?update=Robots\">Update robots database</a> - <a href=\"?Robots=View\">Sample robots file</a> - <a href=\"?Robots=Install\">Install robots file</a>";
			}else{
				Message = "<a href=\"?Settings=Robots\">Robots database</a> - <a href=\"?Robots=View\">Sample robots file</a>";
			}

		//View Robots
		}else if(subaction=="View"){
			done = SendFile(pfc, dll.Path + "robots.txt",!IsHEADRequest,"text/plain");
			Message = "Error reading robots.txt file";
	
		//Install Robots (static+dynamic)
		}else if(subaction=="Install" && Settings.Admin.AllowConfigChanges){
			//src
			dll.SetFileName(dll.Path + "robots.txt");
			CString src_path = dll.Path;
			//dest
			CString dest_path = GetServerVariable(pfc,"APPL_PHYSICAL_PATH");
			if(dest_path.Right(1)!=('\\')){
				dest_path += "\\";
			}
			//copy
			Message  = CHTML::Encode(CWebAdmin::InstallFile("robots.txt",src_path,dest_path)) + "<br/>";
			CString dyn_file = GetDynamicFile();
			if(dyn_file!=""){
				Message += CHTML::Encode(CWebAdmin::InstallFile(dyn_file,src_path,dest_path)) + "<br/>";
			}
			Message += "To make sure bad robots fall for the trap, you should add a hidden link on your main page to the bot trap: <br/><pre>&lt;a href=&quot;/badbottrap&quot;&gt;&lt;/a&gt;</pre>";
		}
	}

	//Headers
	else if(Action=="Headers")
	{	
		if(Settings.Experimental.Headers.InputValidation){

			CFileName fnHeaders = Settings.Headers.Validation.FileStamp.FileName;
			if(subaction=="" || subaction=="Dashboard"){
				if(fnHeaders.FileName.GetLength()>0){
					if(Settings.Admin.AllowConfigChanges){
						Message = "<a href=\"default.asp?file=" + CHTML::Encode(fnHeaders.FileName) + "\">Headers database</a> - <a href=\"default.asp?update=Headers\">Update headers database</a>";
					}else{
						Message = "<a href=\"?Settings=Headers\">Headers database</a>";
					}
				}
			}else if(subaction=="Validators"){
				Message = "Available validators: </strong>" + CHTML::Encode(CStringHelper::ToString(Settings.Headers.Validation.Validation.Order,", ")) + "<strong>";
			}else if(subaction=="Clear" && Settings.Admin.AllowConfigChanges){
				CString location = CWebAdmin::GetQueryStringValue(qs,"Clear");
				if(location=="Headers")
					Settings.Headers.Validation.Headers.Cache.Clear();
			}else if(subaction=="Load" && Settings.Admin.AllowConfigChanges){
				if(Settings.Headers.Validation.ReadFromFile(Settings.Admin.dll.Path + "Headers.xml"))
					Settings.Headers.Validation.Headers.Cache.Clear(); //clear otherwise you'll add duplicates
				else
					Message = "Failed to read the file Headers.xml";
				fnHeaders.SetFileName(Settings.Headers.Validation.FileStamp.FileName);
			}

			CString body("");
			body += CWebAdmin::BuildMenu(Message);
			body += CWebAdmin::AddTitle("HTTP Headers Database");
			body += CWebAdmin::AddParagraph("These are the detected headers for your web application. You can restrict the header values by adding a <a href=\"?Headers=Validators\">validator</a> locally or <a href=\"https://www.aqtronix.com/headers/?Action=ShowAdd\">request a new header validator</a>.");

			if(Settings.Admin.AllowConfigChanges && fnHeaders.FileName.GetLength()>0){
				body += CWebAdmin::AddParagraph("Format: Parameter=Validator");
				CMapStringToString map;
				CString URL = "default.asp?file=" + CURL::Encode(fnHeaders.FileName);

				map.RemoveAll();
				Settings.Headers.Validation.Headers.Cache.ToMap(map);
				body += CWebAdmin::BuildParameterForm("Headers","Headers",map,URL);
			}else{
				if(fnHeaders.FileName.GetLength()==0 && Settings.Admin.AllowConfigChanges){
					//body += CWebAdmin::AddParagraph("Start with creating a template file for <a href=\"?Headers=New\">all sites</a> or for <a href=\"?Headers=NewOwner\">" + CHTML::Encode(CProcessHelper::GetCurrentUserName()) + "</a>.");
					body += CWebAdmin::AddParagraph("Install the Headers Database by clicking <a href=\"default.asp?update=Headers\">download</a> and <a href=\"?Headers=Load\">load</a>.");
				}else if(fnHeaders.FileName.GetLength()>0 && !Settings.Admin.AllowConfigChanges){
					body += CWebAdmin::AddParagraph("Edit the file " + CHTML::Encode(fnHeaders.FileName) + " with the configuration utility.");
				}
				body += "<div class=\"accordion\">\r\n";
				body += CWebAdmin::ToTable("Headers",Settings.Headers.Validation.Headers.Cache);
				body += "</div>\r\n";
			}

			body += "<div class=\"accordion\">\r\n";
			body += CWebAdmin::ToTable("Compiled Validators",Settings.Headers.Validation.Regex,"Pattern","Status");
			body += "</div>\r\n";
			SendPage(pfc,CWebAdmin::BuildPage(Settings.Admin.ServerHeader,body),!IsHEADRequest);
			done = true;
		}
	}

	//Parameters
	else if(Action=="Parameters")
	{
		CString body("");
		CFileName fnParameters = Settings.ApplicationParameters.FileStamp.FileName;
		if(subaction.GetLength()==0 || subaction=="Dashboard" /* to prevent Empty validator detection for Parameter */){
			if(fnParameters.FileName.GetLength()>0){
				if(Settings.Admin.AllowConfigChanges)
					Message = "<a href=\"default.asp?file=" + CHTML::Encode(fnParameters.FileName) + "\">Edit Configuration</a>";
				else
					Message = "<a href=\"?Settings=Parameters\">Configured Parameters</a>";
			}
		}else{
			if(subaction=="Validators"){
				Message = "Available validators: </strong>" + CHTML::Encode(CStringHelper::ToString(Settings.ApplicationParameters.Validation.Order,", ")) + "<strong>";

			}else if(subaction=="New" || subaction=="NewOwner"){
				if(Settings.Admin.AllowConfigChanges){
					CString fn = Settings.ApplicationParameters.FileStamp.FileName;
					if(fn.GetLength()==0){
						fn = dll.Path + "Parameters" + ((subaction=="NewOwner")?("." + CProcessHelper::GetCurrentUserName()):CString("")) + ".xml";
						Settings.ApplicationParameters.Version = Settings.Admin.Version;
					}
					Settings.ApplicationParameters.WriteToFileXML(fn);
					Message = "Saved to file " + CHTML::Encode(fn);
					Settings.ApplicationParameters.ReadFromFile(fn);
					fnParameters.SetFileName(fn);
				}

			}else if(subaction=="Clear"){
				CString location = CWebAdmin::GetQueryStringValue(qs,"Clear");
				if(location.GetLength()>0){
					WebParam* param = NULL;
					if(location=="Query")
						param = &Settings.ApplicationParameters.Query;
					if(location=="Cookie")
						param = &Settings.ApplicationParameters.Cookie;
					if(location=="Post")
						param = &Settings.ApplicationParameters.Post;
					if(param!=NULL){
						param->Cache.Clear();
					}
				}
			}
		}
		if(!done){
			//Parameters view
			body += CWebAdmin::BuildMenu(Message);
			body += CWebAdmin::AddTitle("Web Application Parameters");
			body += CWebAdmin::AddParagraph("These are the detected parameters for your web application. You can restrict the parameter values by adding a <a href=\"?Parameters=Validators\">validator</a>.");

			if(Settings.Admin.AllowConfigChanges && fnParameters.FileName.GetLength()>0){
				body += CWebAdmin::AddParagraph("Format: Parameter=Validator");
				CMapStringToString map;
				CString URL = "default.asp?file=" + CURL::Encode(fnParameters.FileName);

				map.RemoveAll();
				Settings.ApplicationParameters.Query.Cache.ToMap(map);
				body += CWebAdmin::BuildParameterForm("Parameters","Query",map,URL);
				map.RemoveAll();
				Settings.ApplicationParameters.Post.Cache.ToMap(map);
				body += CWebAdmin::BuildParameterForm("Parameters","Post",map,URL);
				map.RemoveAll();
				Settings.ApplicationParameters.Cookie.Cache.ToMap(map);
				body += CWebAdmin::BuildParameterForm("Parameters","Cookie",map,URL);

			}else{
				if(fnParameters.FileName.GetLength()==0 && Settings.Admin.AllowConfigChanges){
					body += CWebAdmin::AddParagraph("Start with creating a template file for <a href=\"?Parameters=New\">all sites</a> or for <a href=\"?Parameters=NewOwner\">" + CHTML::Encode(CProcessHelper::GetCurrentUserName()) + "</a>.");
				}else if(fnParameters.FileName.GetLength()>0 && !Settings.Admin.AllowConfigChanges){
					body += CWebAdmin::AddParagraph("Edit the file " + CHTML::Encode(fnParameters.FileName) + " with the configuration utility.");
				}
				body += "<div class=\"accordion\">\r\n";
				body += CWebAdmin::ToTable("Query",Settings.ApplicationParameters.Query.Cache);
				body += CWebAdmin::ToTable("Post",Settings.ApplicationParameters.Post.Cache);
				body += CWebAdmin::ToTable("Cookie",Settings.ApplicationParameters.Cookie.Cache);
				body += "</div>\r\n";
			}

			body += "<div class=\"accordion\">\r\n";
			body += CWebAdmin::ToTable("Compiled Validators",Settings.ApplicationParameters.Regex,"Pattern","Status");
			body += "</div>\r\n";

			SendPage(pfc,CWebAdmin::BuildPage(Settings.Admin.ServerHeader,body),!IsHEADRequest);
			done = true;
		}

	}

	//Help
	else if(Action=="Help")
	{
		Message = "<a href=\"?ReadMe\">Readme</a> - <a href=\"http://www.aqtronix.com/WebKnight/FAQ/\">FAQ</a> - <a href=\"http://www.aqtronix.com/WebKnight/Support/\">Support</a> - <a href=\"http://www.aqtronix.com/productversion/?product=" + CHTML::Encode(Settings.Admin.ServerHeader) + "\">Check for updates</a>";
	}

	//ReadMe
	else if(Action=="ReadMe")
	{
		done = SendFile(pfc, dll.Path + "readme.htm",!IsHEADRequest);
		Message = "Error reading readme.htm file";
	}

	//Diagnostics
	else if(Action=="Diagnostics")
	{
		Message = "<a href=\"?Echo\">Echo request</a> - <a href=\"?Intercept\">Intercept</a>";
		if(Intercept.IP.GetLength()>0)
			Message += " - <a href=\"?Intercept=Reset\">Reset intercept</a>";
		if(Settings.Admin.AllowConfigChanges){
			//Message += " - <a href=\"default.asp?diag=QueryString\">Query string</a>";
			//Message += " - <a href=\"default.asp?diag=Form\">Form</a>";
			//Message += " - <a href=\"default.asp?diag=Cookies\">Cookies</a>";
			//Message += " - <a href=\"default.asp?diag=ClientCertificate\">Client certificate</a>";
			Message += " - <a href=\"default.asp?diag=ServerVariables\">Server variables</a>";
		}

	}
	else if(Action=="Echo")
	{
		done = true;
		CString req = SerializeRequest(pfc);
		//Can also be seen in Diagnostics -> ServerVariables
		//if(req.Find("\r\nAuthorization:")>-1)
		//	ChangeHeader(req,"Authorization:","**************");
		//if(req.Find("\r\nCookie:")>-1)
		//	ChangeHeader(req,"Cookie:","**************");
		SendPage(pfc,req,!IsHEADRequest,"text/plain");
	}
	else if(Action=="Intercept")
	{
		if(subaction==""){
			if(Intercept.Page.GetLength()==0){
				if(Intercept.IP==""){
					Message = "<a href=\"?Intercept=Reset\">Set intercept IP</a>";
				}else{
					Message = "No message was intercepted yet. <a href=\"?Intercept\">Refresh this page</a> (F5) or <a href=\"?Intercept=Reset\">change intercept IP</a>.";
				}
			}else{
				SendPage(pfc,Intercept.Page,!IsHEADRequest);
				done = true;
			}

		}else if(subaction=="Reset"){
			pos = qs.Find("&IP=");
			if(pos>-1 && pos<qs.GetLength()-4){
				Intercept.IP = qs.Mid(pos+4);
				pos = Intercept.IP.Find("&");
				if(pos>-1){
					Intercept.IP = Intercept.IP.Left(pos);
				}
				Intercept.IP = CURL::Decode(Intercept.IP).Trim();
				Intercept.Page = "";
				if(Intercept.IP==""){
					Message = "Stopped intercepting traffic.";
				}else{
					Message = "Intercepting traffic from IP: " + CHTML::Encode(Intercept.IP) + " (<a href=\"?Intercept\">see the intercepted message</a>)";
				}
			}else{
				Message = "Enter an IP address to intercept its traffic: <form method=\"GET\" action=\"?\"><input type=\"hidden\" name=\"Intercept\" value=\"Reset\"><input type=text name=\"IP\" value=\"" + CHTML::Encode(Intercept.IP) + "\"><input type=\"submit\" name=\"submit\" value=\"Submit\"> (Submit nothing to stop intercepting)</form>";
			}
		}
		
		//add more built-in functions here

	}
	else
	{
		Message = "Function not supported";
	}

	if(!done)
	{
		//Admin Dashboard
		CString body("");
		body += CWebAdmin::BuildMenu(Message);
		body += BuildDashboard();
		SendPage(pfc,CWebAdmin::BuildPage(Settings.Admin.ServerHeader,body),!IsHEADRequest);
	}
}

bool CISAPIFirewall::ShowSettingsFile(PHTTP_FILTER_CONTEXT pfc, CString& Path, bool SendMessageBody)
{
	CString Contents;
	CString ContentType;
	CFileName fn(Path);
	if(fn.ReadFileToString(Path,Contents)){
		if(fn.ExtensionLCase == ".xml"){
			ContentType = "text/xml"; //XML file
			if(Contents.Find("href=\"GUI.xsl\"")>-1){
				Contents.Replace("href=\"GUI.xsl\"","href=\"?GUIXSL\"");
			}else{
				Contents.Replace("<?xml version=\"1.0\" standalone='yes'?>","<?xml version=\"1.0\" standalone='yes'?>\r\n<?xml-stylesheet type=\"text/xsl\" href=\"?GUIXSL\"?>"); //backwards compatible
			}
		}else{
			ContentType = "text/plain"; //INI file
		}
		SendPage(pfc,Contents,SendMessageBody,ContentType);
		return true;
	}else{
		return false;
	}	
}

