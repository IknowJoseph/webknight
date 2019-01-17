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
// HTTPFirewall.h: interface for the CHTTPFirewall class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_HTTPFIREWALL_H__C3EC3F2B_814E_45FB_9DCF_55F4A5BFF13D__INCLUDED_)
#define AFX_HTTPFIREWALL_H__C3EC3F2B_814E_45FB_9DCF_55F4A5BFF13D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "Firewall.h"
#include "URL.h"
#include "Unicode.h"
#include "FileName.h"
#include "HTTPFirewallSettings.h"
#include "WebAdmin.h"

#define CR '\r'
#define LF '\n'
#define CRLF "\r\n"
#define CRLFCRLF "\r\n\r\n"

#define REMOTE_ADDR "REMOTE_ADDR" //change this to use another header to get the client IP
//#define REMOTE_ADDR "HTTP_X_FORWARDED_FOR" //(for custom build request, see e-mail)
//#define REMOTE_ADDR "HTTP_TRUE_CLIENT_IP" //(for custom build request, see e-mail)

#define SITEINSTANCE "W3SVC"		//IIS site labelling
//#define SYSTEM_LOG_BUILD			//log in \system32\LogFiles dir

class CHTTPFirewall : public CFirewall
{
public:
	virtual void SetLoggerFields();
	virtual void LoadCache();
	virtual void ClearCache();
	bool IsExcludedSite(CString& instance);
	bool IsExcludedHost(CString& Host);
	bool IsExcludedIP(CString& IP);
	bool IsExcludedURL(CString& url, CString& Querystring);
	bool IsExcludedReferrerURL(CString& rawUrl);
	bool IsExcludedUserAgent(CString& UserAgent);
	void HackResponseBlockOrMonitor(CString& IP);
	CString GetAlertResponse(bool SendMessageBody = true, bool SendHeaders = true);

	Action ScanRawReferrerURL(LPCTSTR ReferrerUrl, LPCTSTR RequestedURLDecoded, CString& HostHeader, CString& UA);
	Action ScanRawReferrerURL(CURL& ReferrerUrl, CFileName& RequestedFile, CString& HostHeader, CString& UA);
	Action ScanReferrerURL(CString& RefererUrl);
	Action ScanHotLinking(CString& RefererUrl, CFileName& RequestedFile, CString& HostHeader);
	Action ScanParameters(CString& Data, RuleParameters& Rules, WebParam& Parameters, CString Location, TCHAR TokenKey = '&', TCHAR TokenValue = '=', CStringList* pSessions = NULL);
	Action ScanTransferEncoding(CString& TransferEncoding);
	Action ScanContent(CString& ContentType, CString& ContentLength);
	Action ScanUserAgent(CString& UserAgent, CString& IP);
	Action ScanPath(CFileName& fn);
	Action ScanExtensionDoS(CString& ExtensionLCase, CString& IP);
	Action ScanCookie(CString& Cookie, CString& IP, CString& ua, CString& url);
	Action ScanVersion(const CString& Version);
	Action ScanHost(const CString& Version, const CString& Host, const CString& IP);
	Action ScanRawURL(CURL &RawUrl, CString& IP);
	Action ScanVerb(CString Verb, CString& ContentLength, CString& ContentType, CString& TransferEncoding);
	Action ScanFormsAuthentication(CString& Data, CString& IP);
	Action ScanAuthentication(CString& User, CString& Pass, CString& IP);
	Action ScanAccount(CString& User);
	Action ScanFilename(CFileName& fn);
	Action ScanURL(const char* pUrl);
	Action ScanURLDoS(CString& Url);
	Action ScanQuerystring(CString& str, bool doScanParameters = true);
	Action ScanConnection(CString& IP, bool& is_blacklisted, bool& is_monitored);
	Action ScanEntity(CString& Data, CString ContentType, CString& IP, unsigned short depth=0);
	Action ScanRawData(CString& Data, CString& IP);
	Action ScanRawHeaders(CString& Headers);

	//Admin/Stats page
	void Initialize(CString ProductName, LPCTSTR ProductFullName, LPCTSTR UserAgentsFile, CString ConfigurationPath, LPCTSTR LogSuffix = NULL);
	virtual CString BuildDashboard();
	virtual CString BuildStatistics();
	virtual CString BuildIPRanges();
	virtual CString GetStatisticsAdditionalCaches();


	CHTTPFirewall(CHTTPFirewallSettings& _Settings, CLogger& _logger);
	virtual ~CHTTPFirewall();

protected:
	CHTTPFirewallSettings& Settings;

	class _Statistics{
	public:
		CStringCache IP_Authentication;
		CStringCache IP_RequestsLimit;
		CStringCache IP_HACK_Monitored;
		CStringCache IP_HACK_Blocked;
		CStringCache URL_RequestsLimit;
		CStringCache Extension_RequestsLimit;
		CStringCache IP_UserAgent;
		CStringCache IP_RESPONSE_Client_Errors;
		CStringCache IP_RESPONSE_Server_Errors;
		CStringCache Sessions;

		void Clear(){
			IP_Authentication.Clear();
			IP_RequestsLimit.Clear();
			IP_HACK_Monitored.Clear();
			IP_HACK_Blocked.Clear();
			URL_RequestsLimit.Clear();
			Extension_RequestsLimit.Clear();
			IP_UserAgent.Clear();
			IP_RESPONSE_Client_Errors.Clear();
			IP_RESPONSE_Server_Errors.Clear();
			Sessions.Clear();
		}

		void ClearIP(CString IP){
			IP_Authentication.Delete(IP);
			IP_RequestsLimit.Delete(IP);
			IP_HACK_Monitored.Delete(IP);
			IP_HACK_Blocked.Delete(IP);
			//URL_RequestsLimit.Delete(IP); //not an IP
			Extension_RequestsLimit.Delete(IP);
			IP_UserAgent.Delete(IP);
			IP_RESPONSE_Client_Errors.Delete(IP);
			IP_RESPONSE_Server_Errors.Delete(IP);
			//Sessions.Delete(IP); //IP mixed with other strings
		}

	}Statistics;

	static void DebugLog(LPCTSTR Field1, LPCTSTR Field2 = "", LPCTSTR Field3 = "", LPCTSTR FilenameFormat = _T("Debug.log"), bool Escape = false);

private:
	inline void SyncCurrentDates(CStringList& Formats);
};

#endif // !defined(AFX_HTTPFIREWALL_H__C3EC3F2B_814E_45FB_9DCF_55F4A5BFF13D__INCLUDED_)
