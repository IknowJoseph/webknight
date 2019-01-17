/*
    AQTRONIX C++ Library
    Copyright 2009-2010 Parcifal Aertssen

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
#include "StdAfx.h"
#include "WebKnightFilter.h"

///////////////////////////////////////////////////////////////////////
// CWebKnightFilter implementation

CWebKnightFilter::CWebKnightFilter():CISAPIFirewall(Settings,logger)
{
	//fix for GetErrorMessage not being able to load string resources
	AfxSetResourceHandle(CProcessHelper::GetCurrentModule());
	//AFX_MANAGE_STATE(AfxGetStaticModuleState( ));

	CSingleLock lock(&Settings.crit, TRUE);
	Initialize(APP_NAME,APP_FULLNAME,"Robots.xml",Settings.Admin.dll.Path);
	lock.Unlock();
}

CWebKnightFilter::~CWebKnightFilter()
{
	CSingleLock lock(&Settings.crit, TRUE);
	Message("AQTRONIX WebKnight unloaded");
	lock.Unlock();
}

BOOL CWebKnightFilter::GetFilterVersion(PHTTP_FILTER_VERSION pVer)
{
	// Call default implementation for initialization
	CISAPIFilter::GetFilterVersion(pVer);
	// Clear the flags set by base class
	pVer->dwFlags &= ~SF_NOTIFY_ORDER_MASK;

	CSingleLock lock(&Settings.crit, TRUE);

	SetFilterVersion(pVer);

	// Load description string
	TCHAR sz[SF_MAX_FILTER_DESC_LEN+1];
	::LoadString(AfxGetResourceHandle(),IDS_FILTER, sz, SF_MAX_FILTER_DESC_LEN);
	_tcscpy(pVer->lpszFilterDesc, sz);

	lock.Unlock();
	return TRUE;
}

void CWebKnightFilter::LoadCache()
{
	CHTTPFirewall::LoadCache();

	BOT_Blocked.SetMaxAge(CTimeSpan(0,Settings.Robots.BotTimeout>1?Settings.Robots.BotTimeout:1,0,0));
	BOT_RequestsLimit.SetMaxAge(CTimeSpan(0,0,Settings.Robots.DenyAggressive.MaxTime>1?Settings.Robots.DenyAggressive.MaxTime:1,0));
}

void CWebKnightFilter::ClearCache()
{
	CHTTPFirewall::ClearCache();
	BOT_Blocked.Clear();
	BOT_RequestsLimit.Clear();
}

CString CWebKnightFilter::GetStatisticsAdditionalCaches()
{
	CString ret("");
	ret += CWebAdmin::ToTable("Bots - Blocked",BOT_Blocked);
	ret += CWebAdmin::ToTable("Bots - Requests Limit",BOT_RequestsLimit);
	return ret;
}

CString CWebKnightFilter::GetDynamicFile()
{
	if(Settings.Robots.Dynamic){
		return Settings.Robots.DynamicFile;
	}else{
		return CISAPIFirewall::GetDynamicFile();
	}
}

Action CWebKnightFilter::CustomHeaderScanning(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders, CString& ip, CURL& RawUrl, CString& ua, CString& version)
{
	Action action;
	CFileName fn(CURL::Decode(RawUrl.Url));

	//BOTS
	logger.AppendEscape(ua.Left(2048));

	bool bRobotFile(false);

	//BOTS
	if(fn.FileNameLCase=="robots.txt"){
		//BOTS - Robots.txt
		if(Settings.Robots.AllowRobotsFile){
			logger.Append("File access 'robots.txt'");
			bRobotFile = true;
		}
		//BOTS - Block All
		if(Settings.Robots.DenyAll){
			BOT_Blocked.Add(ip,ua);
			Alert("Robots not allowed");
		}
		//BOTS - Deny aggressive - start monitoring
		if(Settings.Robots.DenyAggressive.Enabled){
			//add request to cache to start monitoring
			BOT_RequestsLimit.Add(ip,ua);
		}
		//BOTS - Redirect
		if(Settings.Robots.Dynamic){
			CString urlString(RawUrl.RawUrl);
			CStringHelper::Safe_MakeLower(urlString);
			urlString.Replace("robots.txt",Settings.Robots.DynamicFile);
			TCHAR *newUrlString= urlString.GetBuffer(urlString.GetLength());
			pHeaders->SetHeader(pfc, "url", newUrlString);
			//return SF_STATUS_REQ_HANDLED_NOTIFICATION;
		}
	}else{
		//BOTS - Block Aggressive Bots - monitor subsequent requests after robots.txt
		if(Settings.Robots.DenyAggressive.Enabled){
			if(BOT_RequestsLimit.Exists(ip,ua)){
				//add request to cache
				BOT_RequestsLimit.Add(ip,ua);

				//block if number of requests exceeds certain treshold
				if(BOT_RequestsLimit.Count(ip)>Settings.Robots.DenyAggressive.MaxCount){
					BOT_Blocked.Add(ip,ua);
					Alert("Aggressive robot not allowed");
				}
			}
		}
	}

	//BOTS - Block Bad Bots
	if(Settings.Robots.DenyBad){
		if( DenySequences(RawUrl.Url,Settings.Robots.BadBotTraps,"Bad robot fell for trap: '","'") ){
			BOT_Blocked.Add(ip,ua);
		}
	}

	if(!bRobotFile){
		//BOTS - Block if in list
		if(BOT_Blocked.Exists(ip,ua)){
			action.Set(true);
			Alert("Robot not allowed until timeout expires");
		}

		CString uA = ua;

		//HEADERS: User Agent
		if(version.GetLength()>0 && version!="HTTP/0.9")
			action |= ScanUserAgent(ua,ip);

		//UA ANOMALIES
		if(Settings.Experimental.UserAgent.Anomalies && uA.GetLength()>0 && action.IsEmpty())
			action |= ScanUserAgentAnomalies(pfc,pHeaders,uA);
	}

	return action;
}

Action CWebKnightFilter::ScanUserAgentAnomalies(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders, CString& ua)
{
	Action action;
	int anomalies = 0;

	if(IsInList(ua,Settings.Experimental.UserAgent.Ignore)){
		//ignore

	}else if(IsListItemInString(ua,Settings.Experimental.UserAgent.Browsers)){
		//Browsers

		//require these headers
		if(GetServerVariable(pfc,"HTTP_ACCEPT")=="")
			anomalies++;
		if(GetServerVariable(pfc,"HTTP_ACCEPT_LANGUAGE")=="")
			anomalies++;
		if(GetServerVariable(pfc,"HTTP_ACCEPT_ENCODING")=="")
			anomalies++;

		//if(GetServerVariable(pfc,"HTTP_DNT")=="")
		//	anomalies++;

		//Connection: close
		if(GetServerVariable(pfc,"HTTP_CONNECTION")=="close")
			anomalies += 5;

		//http/1.0
		CString version = GetHeader(pfc,pHeaders,"version");
		if(version=="HTTP/1.0")
			anomalies += 10;

		//unusual http header sequence
		//CString raw = GetServerVariable(pfc,"ALL_RAW");

		//Cookie before Host (is normal in FF)
		//static CString headerorder = CSignatures::RegexPatternHttpHeaderOrder("Cookie","Host");
		//if(Settings.regex_cache.Match(raw,headerorder)
		//	anomalies++;

	}else if(IsListItemInString(ua,Settings.Experimental.UserAgent.FromBots)){

		//Bots with From: header
		if(GetServerVariable(pfc,"HTTP_FROM").GetLength()==0){
			anomalies += 20;
			DebugLog(ua,GetClientIP(pfc),SerializeRequest(pfc),"UserAgent.From.Missing.log",true);
		}

	}else{
		if(Settings.Experimental.UserAgent.AnomaliesLogRequest){
			if(!Settings.Experimental.UserAgent.UA.Exists(ua)){
				Settings.Experimental.UserAgent.UA.Add(ua);

				CString from = GetServerVariable(pfc,"HTTP_FROM");
				if(from.GetLength()>0){
					DebugLog(ua,CString("From:"),from,"UserAgent.From.log");
				}else{					
					DebugLog(ua,GetClientIP(pfc),SerializeRequest(pfc),"UserAgent.New.log",true);
				}
			}
		}
	}

	if(anomalies>0){
		if(anomalies>Settings.Experimental.UserAgent.AnomaliesThreshold){
			action.Set(Settings.Experimental.UserAgent.Anomalies);
			//TODO: EXPERIMENTAL - User Agent Anomalies from logs 2017
			Alert("User agent anomalies detected: " + CStringHelper::Safe_IntToAscii(anomalies),Settings.Experimental.UserAgent.Anomalies);
			if(Settings.Experimental.UserAgent.AnomaliesLogRequest)
				LogRequest(pfc);
		}else{
			//if(anomalies>1 && Settings.Experimental.UserAgent.AnomaliesLogRequest){
			//	DebugLog(ua,CStringHelper::Safe_IntToAscii(anomalies),SerializeRequest(pfc),"UserAgent.Anomalies.log",true);
			//}
		}
	}

	return action;
}
