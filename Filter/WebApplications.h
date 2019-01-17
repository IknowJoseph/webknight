/*
	AQTRONIX WebKnight - ISAPI Filter for securing IIS
	Copyright 2015 Parcifal Aertssen

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
#pragma once

#include "WebKnightSettings.h"

class CWebApplications : public CStringHelper
{
public:
	static bool EnablePaypalIPN(CWebKnightSettings& Settings);
	static bool EnableWebSocket(CWebKnightSettings& Settings);
	static bool EnableWinRM(CWebKnightSettings& Settings);
	static bool EnableBITS(CWebKnightSettings& Settings);
	static bool EnableREST(CWebKnightSettings& Settings);
	static bool EnableJSON(CWebKnightSettings& Settings);
	static bool EnableSOAP(CWebKnightSettings& Settings);
	static bool EnableFileUploads(CWebKnightSettings& Settings);
	static bool EnableUnicode(CWebKnightSettings& Settings);
	static bool EnableIPP(CWebKnightSettings& Settings);
	static bool EnableActiveSync(CWebKnightSettings& Settings);
	static bool EnableOutlookMobileAccess(CWebKnightSettings& Settings);
	static bool EnableRPCoverHTTP(CWebKnightSettings& Settings);
	static bool EnableStaticHTML(CWebKnightSettings& Settings);
	static bool EnableASP(CWebKnightSettings& Settings);
	static bool EnableASPNET(CWebKnightSettings& Settings);
	static bool EnableASPNETMVC(CWebKnightSettings& Settings);
	static bool EnablePHP(CWebKnightSettings& Settings);
	static bool EnableSmallBusinessServer(CWebKnightSettings& Settings);
	static bool EnableCommerceServer(CWebKnightSettings& Settings);
	static bool EnableBizTalkServer(CWebKnightSettings& Settings);
	static bool EnableCertificateServices(CWebKnightSettings& Settings);
	static bool EnableSharePointTeamServices(CWebKnightSettings& Settings);
	static bool EnableSharePointPortalServer(CWebKnightSettings& Settings);
	static bool EnableSharePointOffice2007(CWebKnightSettings& Settings);
	static bool EnableTeamFoundationServer(CWebKnightSettings& Settings);
	static bool EnableVirtualServer2005(CWebKnightSettings& Settings);
	static bool EnableIISADMPWD(CWebKnightSettings& Settings);
	static bool EnableWebDAV(CWebKnightSettings& Settings);
	static bool EnableFrontpageExtensions(CWebKnightSettings& Settings);
	static bool EnableColdfusion(CWebKnightSettings& Settings);
	static bool EnableOutlookWebAccess(CWebKnightSettings& Settings);

public:
	CWebApplications(void);
	virtual ~CWebApplications(void);
};
