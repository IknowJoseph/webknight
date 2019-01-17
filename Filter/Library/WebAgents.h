/*
    AQTRONIX C++ Library
    Copyright 2005-2006 Parcifal Aertssen

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
// WebAgents.h: interface for the CWebAgents class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_WEBAGENTS_H__E994FF85_60F2_4154_8686_146485A4CFD6__INCLUDED_)
#define AFX_WEBAGENTS_H__E994FF85_60F2_4154_8686_146485A4CFD6__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "Settings.h"

class CWebAgent
{
public:
	CStringList UserAgent;
	CStringList UserAgentSequences;
	CStringList IP;
};

class CWebAgents : public CSettings  
{
public:
	CWebAgent DataMiningPublic;
	CWebAgent DataMiningCommercial;
	CWebAgent DownloadManagers;
	CWebAgent EmailHarvesting;
	CWebAgent GuestbookSpammers;
	CWebAgent HackTools;
	CWebAgent ImageDownloaders;
	CWebAgent Indexing;
	CWebAgent Monitoring;
	CWebAgent OfflineBrowsers;
	CWebAgent OtherBad;
	CWebAgent Trademark;
	CWebAgent ValidationTools;
	CWebAgent LinkChecking;
	CWebAgent Browsers;
	CWebAgent MediaPlayers;
	CWebAgent Proxies;
	CWebAgent Adware;
	CWebAgent BrowserExtensions;
	CWebAgent Spyware;
	CWebAgent Editing;
	//CWebAgent Device;
	CWebAgent NewsFeed;
	CWebAgent SearchEngines;
	CWebAgent FilteringSoftware;
	CWebAgent SoftwareComponent;
	CWebAgent Translation;
	CWebAgent SEO;
	CWebAgent MailClients;

	CString ToXML();
	bool ParseXML(CString& key, CString& val);
	bool WriteToFileINI(LPCSTR fn);
	bool ReadFromFileINI(LPCTSTR fn);
	bool WriteToFileXML(LPCTSTR fn);
	void LoadDefaults();
	bool ApplyConstraints();

	CWebAgents();
	virtual ~CWebAgents();

};

#endif // !defined(AFX_WEBAGENTS_H__E994FF85_60F2_4154_8686_146485A4CFD6__INCLUDED_)
