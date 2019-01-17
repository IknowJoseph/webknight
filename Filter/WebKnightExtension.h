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
#if !defined(AFX_WEBKNIGHTEXTENSION_H__A33A37DC_5BA8_41CD_9125_46DC46695866__INCLUDED_)
#define AFX_WEBKNIGHTEXTENSION_H__A33A37DC_5BA8_41CD_9125_46DC46695866__INCLUDED_

// WEBKNIGHTEXTENSION.H - Header file for your Internet Server
//    WebKnightExtension Extension

#include "resource.h"
#include "HTTPFirewall.h"
#include "ISAPIExtension.h"
#include "WebKnightSettings.h"

class CWebKnightExtension : public CISAPIExtension, public CHTTPFirewall
{

private:
	bool OnPassThrough(EXTENSION_CONTROL_BLOCK* pECB);
public:
	virtual DWORD HttpExtensionProc(EXTENSION_CONTROL_BLOCK *pECB);
	DWORD NotSupported(EXTENSION_CONTROL_BLOCK* pECB);
	DWORD PassThrough(EXTENSION_CONTROL_BLOCK* pECB);

	CString GetClientIP(EXTENSION_CONTROL_BLOCK *pECB);
	inline void LogClientInfo(EXTENSION_CONTROL_BLOCK *pECB);
	inline void LogRequestLine(EXTENSION_CONTROL_BLOCK *pECB);

	void HackResponse(EXTENSION_CONTROL_BLOCK *pECB, bool SendMessageBody);

	CWebKnightExtension(CWebKnightSettings& _Settings, CLogger& _logger);
	~CWebKnightExtension();

// Overrides
	// ClassWizard generated virtual function overrides
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//{{AFX_VIRTUAL(CWebKnightExtension)
	public:
	virtual BOOL GetExtensionVersion(HSE_VERSION_INFO* pVer);
	//}}AFX_VIRTUAL
	virtual BOOL TerminateExtension(DWORD dwFlags);

	//// TODO: Add handlers for your commands here.
	//// For example:
	//void Default(CHttpServerContext* p);
	//DECLARE_PARSE_MAP()

	//{{AFX_MSG(CWebKnightExtension)
	//}}AFX_MSG
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_WEBKNIGHTEXTENSION_H__A33A37DC_5BA8_41CD_9125_46DC46695866__INCLUDED)
