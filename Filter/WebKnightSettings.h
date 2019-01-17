/*
	AQTRONIX WebKnight - ISAPI Filter for securing IIS
	Copyright 2002-2014 Parcifal Aertssen

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

// WebKnightSettings.h: interface for the CWebKnightSettings class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_WEBKNIGHTSETTINGS_H__E2FABE74_F5AD_44C6_A64E_FE3890A980EC__INCLUDED_)
#define AFX_WEBKNIGHTSETTINGS_H__E2FABE74_F5AD_44C6_A64E_FE3890A980EC__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "HTTPFirewallSettings.h"

class CWebKnightSettings : public CHTTPFirewallSettings
{
public:
	CString ToXML();
	bool ApplyConstraints();

	//WEB APPLICATIONS;
	class _WebApp{
	public:
		bool Allow_PaypalIPN;
		bool Allow_ASP;
		bool Allow_ASPNET;
		bool Allow_ASPNETMVC;
		bool Allow_SmallBusinessServer;
		bool Allow_CommerceServer;
		bool Allow_BizTalkServer;
		bool Allow_CertificateServices;
		bool Allow_SharePointTeamServices;
		bool Allow_SharePointPortalServer;
		bool Allow_SharePointOffice2007;
		bool Allow_TeamFoundationServer;
		bool Allow_VirtualServer2005;
		bool Allow_IISADMPWD;
		bool Allow_WebDAV;
		bool Allow_Coldfusion;
		bool Allow_FrontpageExtensions;
		bool Allow_OutlookWebAccess;
		bool Allow_OutlookMobileAccess;
		bool Allow_RPCoverHTTP;
		bool Allow_ActiveSync;
		bool Allow_BITS;
		bool Allow_SOAP;
		bool Allow_JSON;
		bool Allow_REST;
		bool Allow_WinRM;
		bool Allow_WebSocket;
		bool Allow_PHP;
		bool Allow_Unicode;
		bool Allow_FileUploads;

		void Clear()
		{
			Allow_FileUploads = false;
			Allow_Unicode = false;
			Allow_OutlookWebAccess = false;
			Allow_OutlookMobileAccess = false;
			Allow_FrontpageExtensions = false;
			Allow_Coldfusion = false;
			Allow_WebDAV = false;
			Allow_IISADMPWD = false;
			Allow_SharePointPortalServer = false;
			Allow_SharePointTeamServices = false;
			Allow_SharePointOffice2007 = false;
			Allow_TeamFoundationServer = false;
			Allow_VirtualServer2005 = false;
			Allow_CertificateServices = false;
			Allow_BizTalkServer = false;
			Allow_CommerceServer = false;
			Allow_SmallBusinessServer = false;
			Allow_ASP = false;
			Allow_ASPNET = false;
			Allow_ASPNETMVC = false;
			Allow_RPCoverHTTP = false;
			Allow_ActiveSync = false;
			Allow_BITS = false;
			Allow_PHP = false;
			Allow_SOAP = false;
			Allow_JSON = false;
			Allow_REST = false;
			Allow_WinRM = false;
			Allow_WebSocket = false;
			Allow_PaypalIPN = false;
		}
	}WebApp;

	//BOTS
	class _Robots{
	public:
		bool AllowRobotsFile;
		bool Dynamic;
		CString DynamicFile;
		bool DenyAll;
		bool DenyBad;
		CStringList BadBotTraps;
		_StringCache DenyAggressive; //don't use RuleStringCache!
		unsigned int BotTimeout;
	}Robots;

	void AddAllPayloads(LPCTSTR item);
	void AddAllList(LPCTSTR item);
	void AddAllRegex(LPCTSTR item, LPCTSTR value, bool AddHeaders = true);
	void ReplaceAllRegex(LPCSTR item, LPCTSTR find, LPCTSTR replacement);
	void ReplaceAllRegex(LPCTSTR find, LPCTSTR replacement);

	void LoadDefaults();
	void Upgrade();
	void Notify(LPCTSTR Message);

	CWebKnightSettings();
	virtual ~CWebKnightSettings();

private:
	void LoadAgents();
	inline void LoadIISDefaults();
	inline void LoadISACompatibility();
	bool ParseXML(CString& key, CString& val);
	bool ReadFromFileINI(LPCTSTR fn);
	bool WriteToFileINI(LPCTSTR fn);
	bool WriteToFileXML(LPCTSTR fn);
protected:
	CString GetXMLWebRobots(CWebKnightSettings& d);
	CString GetXMLWebApplications(CWebKnightSettings& d);
};

#endif // !defined(AFX_WEBKNIGHTSETTINGS_H__E2FABE74_F5AD_44C6_A64E_FE3890A980EC__INCLUDED_)
