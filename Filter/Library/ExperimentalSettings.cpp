/*
    AQTRONIX C++ Library
    Copyright 2016 Parcifal Aertssen

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
#include "ExperimentalSettings.h"

CExperimentalSettings::CExperimentalSettings(void)
{
	LoadDefaults();
}

CExperimentalSettings::~CExperimentalSettings(void)
{
}

void CExperimentalSettings::LoadDefaults()
{
	UserAgent.Anomalies = Action::Disabled;
	UserAgent.AnomaliesThreshold = 11;
	UserAgent.AnomaliesLogRequest = false;

	UserAgent.Ignore.RemoveAll();
	UserAgent.Ignore.AddTail("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"); //From header not always present
	UserAgent.Ignore.AddTail("Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
	UserAgent.Ignore.AddTail("Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)");
	UserAgent.Ignore.AddTail("Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)");
	UserAgent.Ignore.AddTail("Mozilla/5.0 (compatible; DotBot/1.1; http://www.opensiteexplorer.org/dotbot, help@moz.com)");
	UserAgent.Ignore.AddTail("Mozilla/5.0 (compatible; MJ12bot/v1.4.7; http://mj12bot.com/)");
	UserAgent.Ignore.AddTail("Mozilla/5.0 (compatible; linkdexbot/2.0; +http://www.linkdex.com/bots/)");
	//UserAgent.Ignore.AddTail("");
	//UserAgent.Ignore.AddTail("");
	//UserAgent.Ignore.AddTail("");
	//UserAgent.Ignore.AddTail("");
	//UserAgent.Ignore.AddTail("");
	//UserAgent.Ignore.AddTail("");

	UserAgent.Browsers.RemoveAll();
	UserAgent.Browsers.AddTail(" Chrome/");
	UserAgent.Browsers.AddTail(" Firefox/");
	UserAgent.Browsers.AddTail(" Edge/");
	UserAgent.Browsers.AddTail("Trident/");
	UserAgent.Browsers.AddTail("MSIE ");
	UserAgent.Browsers.AddTail("Safari/");
	UserAgent.Browsers.AddTail("Opera");
	//UserAgent.Browsers.AddTail("Qwantify/"); //is a browser extension, but uses HTTP/1.0
	//UserAgent.Browsers.AddTail("");
	//UserAgent.Browsers.AddTail("");
	//UserAgent.Browsers.AddTail("");
	//UserAgent.Browsers.AddTail("");
	//UserAgent.Browsers.AddTail("");

	UserAgent.FromBots.RemoveAll();
	UserAgent.FromBots.AddTail("AdsBot-Google");
	UserAgent.FromBots.AddTail("Barkrowler");
	UserAgent.FromBots.AddTail("bingbot/"); //not always with a From header
	UserAgent.FromBots.AddTail("BUbiNG");
	UserAgent.FromBots.AddTail("Exabot/");
	UserAgent.FromBots.AddTail("Favicon downloader (+https://favico.be/bot.html)");
	UserAgent.FromBots.AddTail("Feedly/");
	UserAgent.FromBots.AddTail("Googlebot"); //not always with a From header (first visit ever to your domain, it is missing a From header)
	UserAgent.FromBots.AddTail("Google-AdWords-Express");
	UserAgent.FromBots.AddTail("Google-Youtube-Links");
	UserAgent.FromBots.AddTail("ips-agent");
	UserAgent.FromBots.AddTail("kulturarw");
	UserAgent.FromBots.AddTail("msnbot");
	UserAgent.FromBots.AddTail("Page2RSS/");
	UserAgent.FromBots.AddTail("picsearch.com");
	UserAgent.FromBots.AddTail("Qwant Research Bot/");
	UserAgent.FromBots.AddTail("SEOkicks-Robot");
	UserAgent.FromBots.AddTail("YandexBot/");
	UserAgent.FromBots.AddTail("YandexImages/");
	//UserAgent.FromBots.AddTail(".exif-search.com"); //not in UserAgents DB???
	//UserAgent.FromBots.AddTail("");
	//UserAgent.FromBots.AddTail("");
	//UserAgent.FromBots.AddTail("");
	//UserAgent.FromBots.AddTail("");
	//UserAgent.FromBots.AddTail("");
	//UserAgent.FromBots.AddTail("");

	Headers.InputValidation = Action::Disabled;
	Headers.LogNewHeaders = false;
	Headers.LogValidationFailures = false;
	Headers.NameRequireRegex.Action = Action::Disabled;
	Headers.NameRequireRegex.Value = "^[a-zA-Z][a-zA-Z0-9_\\-.]+:$";
	Headers.ValidationFailures.SetMaxItems(100);

	Session.Lock = Action::Disabled;
	Session.Timeout = 20; //in min.
	Session.ByIP = true; //can change when people use multiple proxies, open VPN connection etc...
	Session.ByUserAgent = true;
	Session.Excluded.Enabled = true; //maybe only scan asp/php pages?
	Session.Excluded.List.RemoveAll();
	Session.Excluded.List.AddTail("/favicon.ico");

	Post.ScanDataUrl = false;
}

void CExperimentalSettings::Enable()
{
	Session.Lock = Action::Monitor;

	UserAgent.Anomalies = Action::Block;
	UserAgent.AnomaliesLogRequest = true;

	Headers.NameRequireRegex.Action = Action::Block;
	Headers.InputValidation = Action::Block;
	Headers.LogNewHeaders = true;
	Headers.LogValidationFailures = true;

	Post.ScanDataUrl = true;
}

bool CExperimentalSettings::ApplyConstraints()
{
	CSettings::ApplyConstraints();

	return true;
}

bool CExperimentalSettings::ReadFromFileINI(LPCTSTR fn)
{
	const int sz = SETTINGS_MAX_INI_BUF_SIZE;
	//char buf[sz];
	//DWORD l;

	return false;
}

bool CExperimentalSettings::WriteToFileINI(LPCSTR fn)
{
	return false;
}

bool CExperimentalSettings::WriteToFileXML(LPCTSTR fn)
{
	CString xml("");

	//xml += "<!DOCTYPE ExperimentalSettings[\r\n";			//start dtd
	//xml += "<!ELEMENT ExperimentalSettings ANY >\r\n";
	//xml += " ]>\r\n";							//end dtd

	xml += "<ExperimentalSettings Version='" + Safe_DoubleToAscii(Version) + "'>\r\n";	//start entity
	xml += "<Experimental_Settings App='Document' NavigationBar='1'/>\r\n";
	xml += "<Experimental_Settings App='Title'/>\r\n";
	xml += ToXML();
	xml += "</ExperimentalSettings>\r\n";		//end entity
	
	return XML.WriteEntityToFile(fn,xml);
}

bool CExperimentalSettings::ParseXML(CString &key, CString &val)
{
	//if not a valid key
	if (key=="")
		return false;

	CString name = CXML::Decode(CXML::TagName(key));

	if(false){
	}
	else PARSE_XML_RULE(UserAgent,Anomalies,"User_Agent_Anomalies")
	else PARSE_XML_INT(UserAgent,AnomaliesThreshold,"User_Agent_Anomalies_Threshold",)
	else PARSE_XML_BOOL(UserAgent,AnomaliesLogRequest,"User_Agent_Log_Request")
	else PARSE_XML_CSTRINGLIST(UserAgent,Ignore,"User_Agent_Ignore")
	else PARSE_XML_CSTRINGLIST(UserAgent,Browsers,"User_Agent_Browsers")
	else PARSE_XML_CSTRINGLIST(UserAgent,FromBots,"User_Agent_From_Bots")

	else PARSE_XML_RULE(Headers,InputValidation,"Header_Input_Validation")
	else PARSE_XML_BOOL(Headers,LogNewHeaders,"Header_Log_New_Headers")
	else PARSE_XML_BOOL(Headers,LogValidationFailures,"Header_Log_Validation_Failures")
	else PARSE_XML_RULE_STRING(Headers,NameRequireRegex,"Header_Name_Require_Regular_Expression")

	else PARSE_XML_INT(Session,Timeout,"Session_Timeout",)
	else PARSE_XML_RULE(Session,Lock,"Session_Lock")
	else PARSE_XML_BOOL(Session,ByIP,"Session_Lock_By_IP")
	else PARSE_XML_BOOL(Session,ByUserAgent,"Session_Lock_By_User_Agent")
	else PARSE_XML_LIST(Session,Excluded,"Session_Excluded")

	else PARSE_XML_BOOL(Post,ScanDataUrl,"Post_Scan_Data_Urls")

	else{
		return false;	//not parsed
	}
	return true;
}

CString CExperimentalSettings::ToXML()
{
	CString xml("");
	CExperimentalSettings d;
	CString exp(" ");

	xml += XML.AddSeparator("User_Agent");
	WRITE_XML_RULE(UserAgent,Anomalies,"User_Agent_Anomalies",exp)
	WRITE_XML_INT(UserAgent,AnomaliesThreshold,"User_Agent_Anomalies_Threshold",exp)
	WRITE_XML_BOOL(UserAgent,AnomaliesLogRequest,"User_Agent_Log_Request",exp)
	WRITE_XML_CSTRINGLIST(UserAgent,Ignore,"User_Agent_Ignore",exp)
	WRITE_XML_CSTRINGLIST(UserAgent,Browsers,"User_Agent_Browsers",exp)
	WRITE_XML_CSTRINGLIST(UserAgent,FromBots,"User_Agent_From_Bots",exp)

	xml += XML.AddSeparator("Headers");
	WRITE_XML_RULE(Headers,InputValidation,"Header_Input_Validation",exp)
	WRITE_XML_BOOL(Headers,LogNewHeaders,"Header_Log_New_Headers",exp)
	WRITE_XML_BOOL(Headers,LogValidationFailures,"Header_Log_Validation_Failures",exp)
	WRITE_XML_RULE_STRING(Headers,NameRequireRegex,"Header_Name_Require_Regular_Expression",exp)

	xml += XML.AddSeparator("Session");
	WRITE_XML_INT(Session,Timeout,"Session_Timeout",exp)
	WRITE_XML_RULE(Session,Lock,"Session_Lock",exp)
	WRITE_XML_BOOL(Session,ByIP,"Session_Lock_By_IP",exp)
	WRITE_XML_BOOL(Session,ByUserAgent,"Session_Lock_By_User_Agent",exp)
	WRITE_XML_LIST(Session,Excluded,"Session_Excluded",exp,exp)

	xml += XML.AddSeparator("Post");
	WRITE_XML_BOOL(Post,ScanDataUrl,"Post_Scan_Data_Urls",exp)

	return xml;
}