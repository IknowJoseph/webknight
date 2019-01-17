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
// WebAgents.cpp: implementation of the CWebAgents class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "WebAgents.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CWebAgents::CWebAgents()
{
}

CWebAgents::~CWebAgents()
{
}

void CWebAgents::LoadDefaults()
{

}

bool CWebAgents::ApplyConstraints()
{
	CSettings::ApplyConstraints();
	return true;
}

bool CWebAgents::ReadFromFileINI(LPCTSTR fn)
{

#define WEBAGENTS_READFROMFILEINI(var,name) \
		l = GetPrivateProfileSection("User Agents " #name,buf,sz,fn);\
		Split(buf,l,##var.UserAgent);\
		INI.Cleanup(##var.UserAgent);\
		l = GetPrivateProfileSection("User Agent Sequences " #name,buf,sz,fn);\
		Split(buf,l,##var.UserAgentSequences);\
		INI.Cleanup(##var.UserAgentSequences);\
		l = GetPrivateProfileSection("IP Addresses " #name,buf,sz,fn);\
		Split(buf,l,##var.IP);\
		INI.Cleanup(##var.IP);
	try{

		const int sz = SETTINGS_MAX_INI_BUF_SIZE;
		char buf[sz];
		DWORD l;

		//User Agents
		WEBAGENTS_READFROMFILEINI(DataMiningCommercial,DataMining Commercial)
		WEBAGENTS_READFROMFILEINI(DataMiningPublic,DataMining Public)
		WEBAGENTS_READFROMFILEINI(DownloadManagers,Download Managers)
		WEBAGENTS_READFROMFILEINI(EmailHarvesting,Email Harvesting)
		WEBAGENTS_READFROMFILEINI(GuestbookSpammers,Guestbook Spammers)
		WEBAGENTS_READFROMFILEINI(HackTools,Hack Tools)
		WEBAGENTS_READFROMFILEINI(ImageDownloaders,Image Downloaders)
		WEBAGENTS_READFROMFILEINI(Indexing,Indexing)
		WEBAGENTS_READFROMFILEINI(Monitoring,Monitoring)
		WEBAGENTS_READFROMFILEINI(OfflineBrowsers,Offline Browsers)
		WEBAGENTS_READFROMFILEINI(OtherBad,Other Bad)
		WEBAGENTS_READFROMFILEINI(Trademark,Trademark)
		WEBAGENTS_READFROMFILEINI(ValidationTools,Validation Tools)
		WEBAGENTS_READFROMFILEINI(LinkChecking,Link Checking)
		WEBAGENTS_READFROMFILEINI(Browsers,Browsers)
		WEBAGENTS_READFROMFILEINI(MediaPlayers,Media Players)
		WEBAGENTS_READFROMFILEINI(Proxies,Proxies)
		WEBAGENTS_READFROMFILEINI(Adware,Adware)
		WEBAGENTS_READFROMFILEINI(BrowserExtensions,Browser Extensions)
		WEBAGENTS_READFROMFILEINI(Spyware,Spyware)
		WEBAGENTS_READFROMFILEINI(Editing,Editing)
		//WEBAGENTS_READFROMFILEINI(Device,Device)
		WEBAGENTS_READFROMFILEINI(NewsFeed,News Feed)
		WEBAGENTS_READFROMFILEINI(SearchEngines,Search Engines)
		WEBAGENTS_READFROMFILEINI(FilteringSoftware,Filtering Software)
		WEBAGENTS_READFROMFILEINI(SoftwareComponent,Software Component)
		WEBAGENTS_READFROMFILEINI(Translation,Translation)
		WEBAGENTS_READFROMFILEINI(SEO,SEO)
		WEBAGENTS_READFROMFILEINI(MailClients,Mail Clients)

		return true;
	}catch(...){
		LoadDefaults();
		return false;
	}
}

bool CWebAgents::WriteToFileINI(LPCSTR fn)
{
	/* 
	 * Write all settings to a simple INI file
	 * All checks on the file should have been
	 * done before this function is called
	 */

#define WEBAGENTS_WRITETOFILEINI(var,name) \
	WritePrivateProfileSection("User Agents " #name,INI.ToString(##var.UserAgent),fn);\
	WritePrivateProfileSection("User Agent Sequences " #name,INI.ToString(##var.UserAgentSequences),fn);\
	WritePrivateProfileSection("IP Addresses " #name,INI.ToString(##var.IP),fn);\

	try{
	
		//User Agents
		WEBAGENTS_WRITETOFILEINI(DataMiningCommercial,DataMining Commercial)
		WEBAGENTS_WRITETOFILEINI(DataMiningPublic,DataMining Public)
		WEBAGENTS_WRITETOFILEINI(DownloadManagers,Download Managers)
		WEBAGENTS_WRITETOFILEINI(EmailHarvesting,Email Harvesting)
		WEBAGENTS_WRITETOFILEINI(GuestbookSpammers,Guestbook Spammers)
		WEBAGENTS_WRITETOFILEINI(HackTools,Hack Tools)
		WEBAGENTS_WRITETOFILEINI(ImageDownloaders, Image Downloaders)
		WEBAGENTS_WRITETOFILEINI(Indexing,Indexing)
		WEBAGENTS_WRITETOFILEINI(Monitoring,Monitoring)
		WEBAGENTS_WRITETOFILEINI(OfflineBrowsers,Offline Browsers)
		WEBAGENTS_WRITETOFILEINI(OtherBad,Other Bad)
		WEBAGENTS_WRITETOFILEINI(Trademark,Trademark)
		WEBAGENTS_WRITETOFILEINI(ValidationTools,Validation Tools)
		WEBAGENTS_WRITETOFILEINI(LinkChecking,Link Checking)
		WEBAGENTS_WRITETOFILEINI(Browsers,Browsers)
		WEBAGENTS_WRITETOFILEINI(MediaPlayers,Media Players)
		WEBAGENTS_WRITETOFILEINI(Proxies,Proxies)
		WEBAGENTS_WRITETOFILEINI(Adware,Adware)
		WEBAGENTS_WRITETOFILEINI(BrowserExtensions,Browser Extensions)
		WEBAGENTS_WRITETOFILEINI(Spyware,Spyware)
		WEBAGENTS_WRITETOFILEINI(Editing,Editing)
		//WEBAGENTS_WRITETOFILEINI(Device,Device)
		WEBAGENTS_WRITETOFILEINI(NewsFeed,News Feed)
		WEBAGENTS_WRITETOFILEINI(SearchEngines,Search Engines)
		WEBAGENTS_WRITETOFILEINI(FilteringSoftware,Filtering Software)
		WEBAGENTS_WRITETOFILEINI(SoftwareComponent,Software Component)
		WEBAGENTS_WRITETOFILEINI(Translation,Translation)
		WEBAGENTS_WRITETOFILEINI(SEO,SEO)
		WEBAGENTS_WRITETOFILEINI(MailClients,Mail Clients)
		
		return true;

	}catch(...){
		return false;
	}

}

bool CWebAgents::WriteToFileXML(LPCTSTR fn)
{
	CString xml("");

	//xml += "<!DOCTYPE WebAgents[\r\n";			//start dtd
	//xml += "<!ELEMENT WebAgents ANY >\r\n";
	//xml += " ]>\r\n";							//end dtd

	xml += "<WebAgents>\r\n";	//start entity
	xml += "<WebAgents_Database App='Document' NavigationBar='1'/>\r\n";
	xml += "<AQTRONIX_WebAgents_Database App='Title'/>\r\n";
	xml += ToXML();
	xml += "</WebAgents>\r\n";		//end entity
	
	return XML.WriteEntityToFile(fn,xml);
}

bool CWebAgents::ParseXML(CString &key, CString &val)
{
#define WEBAGENTS_PARSEXML(var,key)\
	}else if(name.CompareNoCase("User_Agents_" #key)==0){\
		XML.ToObject(val,##var.UserAgent);\
	}else if(name.CompareNoCase("User_Agents_" #key "_Sequences")==0){\
		XML.ToObject(val,##var.UserAgentSequences);\
	}else if(name.CompareNoCase("IP_Addresses_" #key)==0){\
		XML.ToObject(val,##var.IP);

	//if not a valid key
	if (key=="")
		return false;

	CString name = CXML::Decode(CXML::TagName(key));

	if(false){
	
	//User Agents
	WEBAGENTS_PARSEXML(DataMiningCommercial,Data_Mining_Commercial)
	WEBAGENTS_PARSEXML(DataMiningPublic,Data_Mining_Public)
	WEBAGENTS_PARSEXML(DownloadManagers,Download_Managers)
	WEBAGENTS_PARSEXML(EmailHarvesting,Email_Harvesting)
	WEBAGENTS_PARSEXML(GuestbookSpammers,Guestbook_Spammers)
	WEBAGENTS_PARSEXML(HackTools,Hack_Tools)
	WEBAGENTS_PARSEXML(ImageDownloaders, Image_Downloaders)
	WEBAGENTS_PARSEXML(Indexing,Indexing)
	WEBAGENTS_PARSEXML(Monitoring,Monitoring)
	WEBAGENTS_PARSEXML(OfflineBrowsers,Offline_Browsers)
	WEBAGENTS_PARSEXML(OtherBad,Other_Bad)
	WEBAGENTS_PARSEXML(Trademark,Trademark)
	WEBAGENTS_PARSEXML(ValidationTools,Validation_Tools)
	WEBAGENTS_PARSEXML(LinkChecking,Link_Checking)
	WEBAGENTS_PARSEXML(Browsers,Browsers)
	WEBAGENTS_PARSEXML(MediaPlayers,Media_Players)
	WEBAGENTS_PARSEXML(Proxies,Proxies)
	WEBAGENTS_PARSEXML(Adware,Adware)
	WEBAGENTS_PARSEXML(BrowserExtensions,Browser_Extensions)
	WEBAGENTS_PARSEXML(Spyware,Spyware)
	WEBAGENTS_PARSEXML(Editing,Editing)
	//WEBAGENTS_PARSEXML(Device,Device)
	WEBAGENTS_PARSEXML(NewsFeed,News_Feed)
	WEBAGENTS_PARSEXML(SearchEngines,Search_Engines)
	WEBAGENTS_PARSEXML(FilteringSoftware,Filtering_Software)
	WEBAGENTS_PARSEXML(SoftwareComponent,Software_Component)
	WEBAGENTS_PARSEXML(Translation,Translation)
	WEBAGENTS_PARSEXML(SEO,SEO)
	WEBAGENTS_PARSEXML(MailClients,Mail_Clients)

	}else{
		return false;	//not parsed
	}
	return true;
}

CString CWebAgents::ToXML()
{
	CString xml("");

#define WEBAGENTS_GETXML(var,name,explanation) \
	xml += XML.AddSeparator(#name##); \
	xml += XML.ToXML("User_Agents_" #name,##var.UserAgent,explanation);\
	xml += XML.ToXML("User_Agents_" #name "_Sequences",##var.UserAgentSequences,explanation);\
	xml += XML.ToXML("IP_Addresses_" #name,##var.IP,explanation);

	//User Agents & Sequences & IP Address
	WEBAGENTS_GETXML(DataMiningCommercial,Data_Mining_Commercial,"")
	WEBAGENTS_GETXML(DataMiningPublic,Data_Mining_Public,"")
	WEBAGENTS_GETXML(DownloadManagers,Download_Managers,"")
	WEBAGENTS_GETXML(EmailHarvesting,Email_Harvesting,"")
	WEBAGENTS_GETXML(GuestbookSpammers,Guestbook_Spammers,"")
	WEBAGENTS_GETXML(HackTools,Hack_Tools,"")
	WEBAGENTS_GETXML(ImageDownloaders,Image_Downloaders,"")
	WEBAGENTS_GETXML(Indexing,Indexing,"")
	WEBAGENTS_GETXML(Monitoring,Monitoring,"")
	WEBAGENTS_GETXML(OfflineBrowsers,Offline_Browsers,"")
	WEBAGENTS_GETXML(OtherBad,Other_Bad,"")
	WEBAGENTS_GETXML(Trademark,Trademark,"")
	WEBAGENTS_GETXML(ValidationTools,Validation_Tools,"")
	WEBAGENTS_GETXML(LinkChecking,Link_Checking,"")
	WEBAGENTS_GETXML(Browsers,Browsers,"")
	WEBAGENTS_GETXML(MediaPlayers,Media_Players,"")
	WEBAGENTS_GETXML(Proxies,Proxies,"")
	WEBAGENTS_GETXML(Adware,Adware,"")
	WEBAGENTS_GETXML(BrowserExtensions,Browser_Extensions,"")
	WEBAGENTS_GETXML(Spyware,Spyware,"")
	WEBAGENTS_GETXML(Editing,Editing,"")
	//WEBAGENTS_GETXML(Device,Device,"")
	WEBAGENTS_GETXML(NewsFeed,News_Feed,"")
	WEBAGENTS_GETXML(SearchEngines,Search_Engines,"")
	WEBAGENTS_GETXML(FilteringSoftware,Filtering_Software,"")
	WEBAGENTS_GETXML(SoftwareComponent,Software_Component,"")
	WEBAGENTS_GETXML(Translation,Translation,"")
	WEBAGENTS_GETXML(SEO,SEO,"")
	WEBAGENTS_GETXML(MailClients,Mail_Clients,"")

	return xml;
}	
