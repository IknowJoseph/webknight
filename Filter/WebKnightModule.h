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
#pragma once

#include "Globals.h"
#include "WebKnightSettings.h"
#include "HTTPFirewall.h"
#include "IISModule.h"

class CWebKnightModule : public CIISModule, public CHTTPFirewall
{
private:
	CString GetClientIP(IHttpContext* pHttpContext);
	void HackResponse(IHttpContext* pHttpContext, bool SendMessageBody);
	inline void LogClientInfo(IHttpContext* pHttpContext);
	inline void LogRequestLine(IHttpContext* pHttpContext);

public:
	CWebKnightSettings Settings;
	CLogger Logger;

	//Events
    GLOBAL_NOTIFICATION_STATUS OnGlobalPreBeginRequest(IN IPreBeginRequestProvider * pProvider);

	CWebKnightModule(void);
	virtual ~CWebKnightModule(void);
};