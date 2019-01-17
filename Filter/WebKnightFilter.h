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
#pragma once

#include "resource.h"

#include "Globals.h"
//if you get an error on this line below, make sure to add the "Library" folder to your Visual Studio directories (Tools->Options->Directories)
#include "ISAPIFirewall.h"
#include "WebKnightSettings.h"

class CWebKnightFilter: public CISAPIFirewall
{
	CStringCache BOT_Blocked;
	CStringCache BOT_RequestsLimit;

public:
	CWebKnightSettings Settings;
	CLogger logger;

	CString GetDynamicFile();
	Action ScanUserAgentAnomalies(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders, CString& ua);
	Action CustomHeaderScanning(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders, CString& ip, CURL& RawUrl, CString& ua, CString& version);
	CWebKnightFilter();
	~CWebKnightFilter();

// Overrides
	// ClassWizard generated virtual function overrides
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//{{AFX_VIRTUAL(CWebKnightFilter)
	public:
	virtual BOOL GetFilterVersion(PHTTP_FILTER_VERSION pVer);
	//}}AFX_VIRTUAL

	//{{AFX_MSG(CWebKnightFilter)
	//}}AFX_MSG

	virtual void LoadCache();
	virtual void ClearCache();
	virtual CString GetStatisticsAdditionalCaches();
};
