/*
	AQTRONIX WebKnight - ISAPI Filter for securing IIS
	Copyright 2012-2015 Parcifal Aertssen

	This file is part of AQTRONIX WebKnight.

    AQTRONIX WebKnight is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation; either version 2 of the
	License, or (at your option) any later version.

    AQTRONIX WebKnight is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with AQTRONIX WebKnight; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/
#include "StdAfx.h"
#include "WebKnightModule.h"

//http://msdn.microsoft.com/en-us/library/ms690697%28v=vs.90%29.aspx
//http://msdn.microsoft.com/en-us/library/ms689348%28v=vs.90%29.aspx
//http://msdn.microsoft.com/en-us/library/ms693073%28v=vs.90%29.aspx

CWebKnightModule::CWebKnightModule(void):CHTTPFirewall(Settings,Logger)
{
	//fix for GetErrorMessage not being able to load string resources
	AfxSetResourceHandle(CProcessHelper::GetCurrentModule());
	//AFX_MANAGE_STATE(AfxGetStaticModuleState( ));

	CSingleLock lock(&Settings.crit, TRUE);

	//TODO: MODULE - use same file as ISAPI filter
	Initialize(APP_NAME,APP_FULLNAME,"Robots.xml",Settings.Admin.dll.Path,".Module");

	//Message("AQTRONIX WebKnight module loaded");
	lock.Unlock();
}

CWebKnightModule::~CWebKnightModule(void)
{
	CSingleLock lock(&Settings.crit, TRUE);
	Message("AQTRONIX WebKnight unloaded");
	lock.Unlock();
}

// Process a GL_PRE_BEGIN_REQUEST notification.
GLOBAL_NOTIFICATION_STATUS CWebKnightModule::OnGlobalPreBeginRequest(IN IPreBeginRequestProvider * pProvider)
{
	try{

		//UNREFERENCED_PARAMETER(pProvider);
		IHttpContext* pc = pProvider->GetHttpContext();
	    
		//Not supported message
		//WriteEventLog("This version of WebKnight does not support IIS Module interface.");
		//SendPage(pc, "This version of WebKnight does not support IIS Module interface.");
		//return GL_NOTIFICATION_HANDLED;

		CString instance = GetServerVariable(pc,"INSTANCE_ID");
		CString host(GetHeader(pc,"Host"));

		CSingleLock lock(&Settings.crit, TRUE);
			
		UpdateSettings();
		
		logger.NewEntry(SITEINSTANCE + instance);
		logger.Append("OnGlobalPreBeginRequest");
		LogClientInfo(pc);
			
		Action action;
		bool IsHEADRequest(false);
		bool logonly(Settings.Response.LogOnly);
		bool respdrop(Settings.HTTPResponse.DropConnection);
		bool is_blacklisted(false);

		CString IP(GetClientIP(pc));
		if(!IsExcludedSite(instance) && !IsExcludedIP(IP)){

			IHttpRequest* pRequest = pc->GetRequest();
			if(pRequest != NULL){

				HTTP_REQUEST* pRawRequest = pRequest->GetRawHttpRequest();
				if(pRawRequest != NULL){

					//excluded url+querystring or host
					CURL RawUrl(pRawRequest->pRawUrl);
					CString ua(GetHeader(pc,"User-Agent"));
					if(IsExcludedURL(RawUrl.Url,RawUrl.Querystring) || IsExcludedHost(host) || IsExcludedUserAgent(ua)){
						//do nothing
					}else{	

						CString Verb(pRequest->GetHttpMethod());
						IsHEADRequest = (Verb=="HEAD"); //do not send message body if HEAD request (RFC compliant)

						//ENTITY
						DWORD size = pRequest->GetRemainingEntityBytes();
						CString ContentType = GetHeader(pc,"Content-Type");
						CString ContentLength = GetHeader(pc,"Content-Length");

						//TODO: MODULE 5.0 - remove this
						logger.Append(Verb);
						logger.Append(RawUrl.RawUrl);
						//logger.Append((int)size);
						
						CString data("");
						if( !(Settings.Admin.Enabled && Settings.Admin.AllowConfigChanges && Settings.IPRanges.Admin.IsInList(IP) && RawUrl.StartsWith(Settings.Admin.Url)) ){ //exclude web admin settings submit

							if(size>0 || ContentLength.GetLength()>1 || ContentLength!="0"){ //size can be 0 even if request contains data (see bugs in IIS)
								//TODO: MODULE - scan smaller than max content length
								if(size < atol(Settings.ContentType.MaxContentLength.Value)){
									logger.Append(ContentType);
									data = GetRawData(pProvider,pRequest);
									if(data.GetLength()>0)
										action |= ScanEntity(data, ContentType, IP);
								}
							}

						}
						//TODO: MODULE - more scanning
						//if(version.GetLength()>0 && version!="HTTP/0.9")
						//	action |= ScanUserAgent(ua,IP);

						//CONNECTION - Monitoring
						if(Settings.Connection.MonitorAddresses.Enabled && data.GetLength()>0){
							if(Settings.IPRanges.Monitor.IsInList(IP)){
								logger.Append("MONITORED: IP address '" + IP + "'");
								logger.AppendEscape(data);
								logger.Flush();
							}
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
			if(!is_blacklisted){
				HackResponseBlockOrMonitor(IP);			//block or monitor IP address
			}
			if(!logonly)								//if we have to do more than logging
				HackResponse(pc,!IsHEADRequest);		//show page
			lock.Unlock();								//unlock globals
			if(logonly){								//if we are only here to log
				return GL_NOTIFICATION_CONTINUE;
			}else{										//if we have to do more than logging
				IHttpResponse* pHttpResponse = pc->GetResponse();
				if(pHttpResponse != NULL){
					pHttpResponse->DisableKernelCache();	//disable response caching
					DWORD cbSent = 0;
					pHttpResponse->Flush(FALSE,FALSE,&cbSent);	//flush response (fix issue: "The custom error module does not recognize this error.") //don't use Async (crashes application pool)
					if(respdrop)
						pHttpResponse->ResetConnection();
				}
				pc->SetRequestHandled();	//make sure IIS does nothing with request
				return GL_NOTIFICATION_HANDLED;		//no further global level notifications
			}
		}else{
			if((action.Status[Action::Monitor] || Settings.Logging.LogAllowed) && logger.HasEntry()){//do not log allowed requests if asked
				logger.Append("ALLOWED");
				logger.Flush();						
			}else{
				logger.Cancel();						//clear the log entry
			}
			lock.Unlock();								//unlock globals
			return GL_NOTIFICATION_CONTINUE;
		}
		return GL_NOTIFICATION_CONTINUE;

	}catch(...){
		logger.NewEntryFlush("ERROR: OnGlobalPreBeginRequest fatal error");
		return GL_NOTIFICATION_CONTINUE;
	}
}

CString CWebKnightModule::GetClientIP(IHttpContext* pHttpContext)
{
	CString IP("");
	//get custom header like X-Forwarded-For
	if(Settings.Connection.ClientIPVariable.GetLength()>0){
		IP = GetServerVariable(pHttpContext,Settings.Connection.ClientIPVariable.GetBuffer(0));
		//if multiple X-Forwarded-For headers are present, only use the last one, others can be spoofed
		int pos = IP.ReverseFind(',');
		if(pos>-1 && pos<IP.GetLength()){
			IP = IP.Mid(pos+1,IP.GetLength()-pos-1).Trim();
		}
	}
	//get standard header if custom header is not present
	if(IP == ""){
		IP = GetServerVariable(pHttpContext,REMOTE_ADDR);
	}
	return IP;
}

void CWebKnightModule::HackResponse(IHttpContext* pHttpContext, bool SendMessageBody)
{
	IHttpResponse* pHttpResponse = pHttpContext->GetResponse();
	if(pHttpResponse != NULL){

		//Server header (also needs to be done for redirect)
		pHttpResponse->ClearHeaders();
		if(!Settings.ResponseMonitor.RemoveServerHeader){
			if(Settings.ResponseMonitor.ChangeServerHeader){
				pHttpResponse->SetHeader("Server", Settings.ResponseMonitor.ServerHeader, Settings.ResponseMonitor.ServerHeader.GetLength(),TRUE);
			}else{
				pHttpResponse->SetHeader("Server", Settings.Admin.ServerHeader, Settings.Admin.ServerHeader.GetLength(),TRUE);
			}
		}

		if(Settings.HTTPResponse.Directly){
			//direct response to client (writeclient)
			//SendResponse(pHttpContext,GetAlertResponse(SendMessageBody));

			//response status
			if(Settings.HTTPResponse.UseStatus){
				pHttpResponse->SetStatus(Settings.HTTPResponse.StatusCode,Settings.HTTPResponse.StatusMessage);
			}

			_tzset();
			CString d = CTime::GetCurrentTime().FormatGmt("%a, %d %b %Y %H:%M:%S GMT");
			CString length = CStringHelper::Safe_IntToAscii(Settings.HTTPResponse.Contents.GetLength());
			pHttpResponse->SetHeader("Date",d,d.GetLength(), TRUE);
			pHttpResponse->SetHeader("Content-Type","text/html; charset=windows-1252", 31, TRUE);
			pHttpResponse->SetHeader("Content-Length", length, length.GetLength(), TRUE);
			pHttpResponse->SetHeader("Pragma", "no-cache", 8, TRUE);
			pHttpResponse->SetHeader("Cache-control", "no-cache", 8, TRUE);
			pHttpResponse->SetHeader("Expires", d, d.GetLength(), TRUE);

			if(SendMessageBody)
				WriteClient(pHttpContext,Settings.HTTPResponse.Contents);

		}else if(Settings.HTTPResponse.Redirect){
			//redirect request to a url
			CString buf = Settings.HTTPResponse.RedirectURL;
			DWORD szbuf(buf.GetLength());
			pHttpResponse->Redirect(buf.GetBuffer(0));

		}else if(Settings.HTTPResponse.UseStatus){
			//respond with special header only
			pHttpResponse->SetStatus(Settings.HTTPResponse.StatusCode,Settings.HTTPResponse.StatusMessage);
		}
	}
}

inline void CWebKnightModule::LogClientInfo(IHttpContext* pHttpContext)
{
	if(Settings.Logging.LogClientIP) logger.Append(GetClientIP(pHttpContext));
	if(Settings.Logging.LogUserName) logger.Append(GetServerVariable(pHttpContext,"LOGON_USER"));
	if(Settings.HTTPLogging.Log_HTTP_VIA) logger.Append(GetServerVariable(pHttpContext,"HTTP_VIA"));
	if(Settings.HTTPLogging.Log_HTTP_X_FORWARDED_FOR) logger.Append(GetServerVariable(pHttpContext,"HTTP_X_FORWARDED_FOR"));
	if(Settings.HTTPLogging.LogHostHeader) logger.Append(GetServerVariable(pHttpContext,"HTTP_HOST"));
	if(Settings.HTTPLogging.LogUserAgent) logger.Append(GetServerVariable(pHttpContext,"HTTP_USER_AGENT"));
}

inline void CWebKnightModule::LogRequestLine(IHttpContext *pHttpContext)
{
	logger.Append(GetServerVariable(pHttpContext,"REQUEST_METHOD"));
	logger.Append(GetServerVariable(pHttpContext,"SCRIPT_NAME"));
	logger.Append(GetServerVariable(pHttpContext,"PATH_INFO"));
	logger.Append(GetServerVariable(pHttpContext,"QUERY_STRING"));
}

// Create the module's exported registration function.
HRESULT __stdcall RegisterModule(DWORD dwServerVersion, IHttpModuleRegistrationInfo * pModuleInfo, IHttpServer * pGlobalInfo)
{
    UNREFERENCED_PARAMETER(dwServerVersion);
    UNREFERENCED_PARAMETER(pGlobalInfo);

	//http://msdn.microsoft.com/en-us/library/ms693073%28v=vs.90%29.aspx

    // Create an instance of the global module class.
	CWebKnightModule * pModule = new CWebKnightModule();
    // Test for an error.
    if (NULL == pModule){
        return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
    }

	HRESULT hr;

    // Set the global notifications and exit.
	//TODO: MODULE - more events
	/*
	if(Settings.Authentication.NotifyAuthentication)
		RQ_AUTHENTICATE_REQUEST -> OnAuthentication
	RQ_AUTHORIZE_REQUEST -> 
	RQ_MAP_PATH -> OnUrlMap
	RQ_SEND_RESPONSE
	*/
	//hr = pModuleInfo->SetRequestNotifications(pModule, RQ_BEGIN_REQUEST, NULL);
    hr = pModuleInfo->SetGlobalNotifications(pModule, GL_PRE_BEGIN_REQUEST);
	if(FAILED(hr))
		return hr;

	// Set priority
	if(pModule->Settings.Engine.AllowLateScanning){
		hr = pModuleInfo->SetPriorityForGlobalNotification(GL_PRE_BEGIN_REQUEST, PRIORITY_ALIAS_LOW);
	}else{
		hr = pModuleInfo->SetPriorityForGlobalNotification(GL_PRE_BEGIN_REQUEST, PRIORITY_ALIAS_HIGH); //PRIORITY_ALIAS_FIRST ?
	}
	if(FAILED(hr))
		return hr;

	return S_OK;
}