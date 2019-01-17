/*
    AQTRONIX C++ Library
    Copyright 2004-2016 Parcifal Aertssen

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
// HTTPFirewallSettings.cpp: implementation of the CHTTPFirewallSettings class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "HTTPFirewallSettings.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CHTTPFirewallSettings::CHTTPFirewallSettings()
{
	LoadDefaults(); //always load defaults (failover redundancy)
}

CHTTPFirewallSettings::~CHTTPFirewallSettings()
{

}

void CHTTPFirewallSettings::LoadDefaults()
{
	Admin.ServerHeader = "CHTTPFirewall/3.0";
	HTTPResponse.Contents = "HTTP Firewall Alert";
}

bool CHTTPFirewallSettings::ProcessFile(LPCTSTR fn)
{
	//if file is a urlscan.ini file
	CFileName cfn(fn);
	if(cfn.FileNameLCase == "urlscan.ini"){		//urlscan.ini file
		return ReadFromFileURLScan(fn);
	}else if(cfn.ExtensionLCase == ".ini"){		//.ini file
		return ReadFromFileINI(fn);
	}else if(cfn.ExtensionLCase == ".xml"){		//.xml file
		return ReadFromFileXML(fn);
	}else{
		return false;							//unknown file type
	}
}

bool CHTTPFirewallSettings::ReadFromFileURLScan(LPCTSTR fn)
{
	/* Read settings from a urlscan.ini file
	 * All checks on the file (exists? access allowed? ...)
	 * should have been done before this function is called
	 */
	try{
		const int sz = SETTINGS_MAX_INI_BUF_SIZE;
		char buf[sz];

		//[options]
		Verbs.AllowVerbs.Action = GetPrivateProfileInt("options","UseAllowVerbs",Verbs.AllowVerbs.Action,fn);
		Verbs.DenyVerbs.Action = !GetPrivateProfileInt("options","UseAllowVerbs",!Verbs.DenyVerbs.Action,fn);
		Extensions.Allow.Action = GetPrivateProfileInt("options","UseAllowExtensions",Extensions.Allow.Action,fn);
		Extensions.Deny.Action = !GetPrivateProfileInt("options","UseAllowExtensions",!Extensions.Deny.Action,fn);
		Path.Dot = !GetPrivateProfileInt("options","AllowDotInPath",!Path.Dot,fn);
		Logging.Enabled = GetPrivateProfileInt("options","EnableLogging",Logging.Enabled,fn)>0;
		Engine.AllowLateScanning = GetPrivateProfileInt("options","AllowLateScanning",Engine.AllowLateScanning,fn)>0;
		
		CString url(HTTPResponse.RedirectURL);
		GetPrivateProfileString("options","RejectResponseUrl","",buf,sz,fn);
		HTTPResponse.RedirectURL = buf; INI.Cleanup(HTTPResponse.RedirectURL);
		if(HTTPResponse.RedirectURL=="") HTTPResponse.RedirectURL=url;
		HTTPResponse.Redirect = !GetPrivateProfileInt("options","UseFastPathReject",!HTTPResponse.Redirect,fn);
		HTTPResponse.Directly = GetPrivateProfileInt("options","UseFastPathReject",0,fn)>0;

		ResponseMonitor.RemoveServerHeader = GetPrivateProfileInt("options","RemoveServerHeader",ResponseMonitor.RemoveServerHeader,fn)>0;
		GetPrivateProfileString("options","AlternateServerName","",buf,sz,fn);
		ResponseMonitor.ServerHeader = buf; INI.Cleanup(ResponseMonitor.ServerHeader);
		ResponseMonitor.ChangeServerHeader = ResponseMonitor.ServerHeader.GetLength()>0;

		CString ldir(Logging.LogDirectory);
		GetPrivateProfileString("options","LoggingDirectory","",buf,sz,fn);
		Logging.LogDirectory = buf; INI.Cleanup(Logging.LogDirectory);
		if(Logging.LogDirectory=="") Logging.LogDirectory=ldir;

		//NormalizeURLBeforeScan = GetPrivateProfileInt("options","NormalizeURLBeforeScan",1,fn);
		//VerifyNormalization = GetPrivateProfileInt("options","VerifyNormalization",1,fn);
		URL.HighBitShellcode = !GetPrivateProfileInt("options","AllowHighBitCharacters",!URL.HighBitShellcode,fn);
	
		//LogLongUrls = GetPrivateProfileInt("options","LogLongUrls",0,fn);
		//PerDayLogging = GetPrivateProfileInt("options","PerDayLogging",1,fn);
		Logging.PerProcess = GetPrivateProfileInt("options","PerProcessLogging",0,fn)>0;
		
		DWORD l;

		//[AllowVerbs]
		l = GetPrivateProfileSection("AllowVerbs",buf, sz,fn);
		Split(buf,l,Verbs.AllowVerbs.List);
		INI.Cleanup(Verbs.AllowVerbs.List);
		
		//[DenyVerbs]
		l = GetPrivateProfileSection("DenyVerbs",buf, sz,fn);
		Split(buf,l,Verbs.DenyVerbs.List);
		INI.CleanupUCase(Verbs.DenyVerbs.List);
		
		//[DenyHeaders]
		l = GetPrivateProfileSection("DenyHeaders",buf, sz,fn);
		Split(buf,l,Headers.DenyHeaders.List);
		INI.Cleanup(Headers.DenyHeaders.List);
		Headers.DenyHeaders.Action = l>0;

		//[AllowExtensions]
		l = GetPrivateProfileSection("AllowExtensions",buf, sz,fn);
		Split(buf,l,Extensions.Allow.List);
		if(l) Extensions.Allow.List.AddHead("");			//always allow default document!!!
		INI.CleanupLCase(Extensions.Allow.List);

		//[DenyExtensions]
		l = GetPrivateProfileSection("DenyExtensions",buf, sz,fn);
		Split(buf,l,Extensions.Deny.List);
		INI.CleanupLCase(Extensions.Deny.List);
		
		//[DenyUrlSequences]
		l = GetPrivateProfileSection("DenyUrlSequences",buf, sz,fn);
		Split(buf,l,URL.DenySequences.List);
		INI.CleanupLCase(URL.DenySequences.List);
		URL.DenySequences.Action = l>0;

		//[AlwaysAllowedUrls]
		l = GetPrivateProfileSection("AlwaysAllowedUrls",buf, sz,fn);
		Split(buf,l,URL.ExcludedURL.List);
		INI.Cleanup(URL.ExcludedURL.List);
		URL.ExcludedURL.Enabled = l>0;

		//[AlwaysAllowedQueryStrings]
		l = GetPrivateProfileSection("AlwaysAllowedQueryStrings",buf, sz,fn);
		Split(buf,l,QueryString.ExcludedQueryString.List);
		INI.Cleanup(QueryString.ExcludedQueryString.List);
		QueryString.ExcludedQueryString.Enabled = l>0;

		//[RequestLimits]
		GetPrivateProfileString("RequestLimits","MaxAllowedContentLength",ContentType.MaxContentLength.Value,buf,sz,fn);
		ContentType.MaxContentLength.Value = buf; INI.Cleanup(ContentType.MaxContentLength.Value);
		ContentType.MaxContentLength.Action = ContentType.MaxContentLength.Value.GetLength()>0;

		URL.MaxLength.Value = GetPrivateProfileInt("RequestLimits","MaxUrl",URL.MaxLength.Value,fn);
		URL.MaxLength.Action = URL.MaxLength.Value>0;

		QueryString.MaxLength.Value = GetPrivateProfileInt("RequestLimits","MaxQueryString",QueryString.MaxLength.Value,fn);
		QueryString.MaxLength.Action = QueryString.MaxLength.Value>0;

		l = GetPrivateProfileSection("RequestLimits",buf, sz,fn);
		CStringList MaxLimits; POSITION oldpos;
		Split(buf,l,MaxLimits);
		POSITION pos = MaxLimits.GetHeadPosition();
		while (pos != NULL){
			oldpos = pos;
			CString& str = MaxLimits.GetNext(pos);
			INI.Cleanup(str);
			if (str.Left(4)!="Max-")
				MaxLimits.RemoveAt(oldpos);
		}
		if(l>0){
			Headers.MaxHeaders.Map.RemoveAll();	//if section is found, remove defaults
			pos = MaxLimits.GetHeadPosition();
			CString val; int poseq;
			while (pos!=NULL){
				CString& str = MaxLimits.GetNext(pos);
				poseq = str.Find('=');
				if(poseq!=-1){
					if(str.Mid(poseq+1) != "")
						Headers.MaxHeaders.Map.SetAt(str.Mid(4,poseq-4)+":",str.Mid(poseq+1));
				}
			}
			Headers.MaxHeaders.Action = Action::Block;
		}else{
			Headers.MaxHeaders.Action = Action::Disabled;
		}

		return true;
	}catch(...){
		LoadDefaults();
		return false;
	}
}

bool CHTTPFirewallSettings::ReadFromFileINI(LPCTSTR fn)
{
	try{
		const int sz = SETTINGS_MAX_INI_BUF_SIZE;
		char buf[sz];
		DWORD l;

		CFirewallSettings::ReadFromFileINI(fn);

		//Scanning Engine
		READ_INI_BOOL(Engine,AllowLateScanning)
		READ_INI_BOOL(Engine,ScanNonSecurePort)
		READ_INI_BOOL(Engine,ScanSecurePort)
		READ_INI_LIST(Engine,ExcludedInstances,INI.Cleanup)
				
		//Intrusion Response Handling
		_HTTPResponse& Response = HTTPResponse;
		READ_INI_BOOL(Response,Directly)
		READ_INI_BOOL(Response,Redirect)
		READ_INI_STRING(Response,RedirectURL)
		READ_INI_BOOL(Response,UseStatus)
		READ_INI_STRING(Response,Status)
		READ_INI_BOOL(Response,DropConnection)
		READ_INI_BOOL(Response,MonitorIP)
		READ_INI_INT(Response,MonitorIPTimeout)
		READ_INI_CACHE(Response,BlockIP)

		//Logging
		_HTTPLogging& Logging = HTTPLogging;
		READ_INI_BOOL(Logging,Log_HTTP_VIA)
		READ_INI_BOOL(Logging,Log_HTTP_X_FORWARDED_FOR)
		READ_INI_BOOL(Logging,LogHostHeader)
		READ_INI_BOOL(Logging,LogUserAgent)

		//Connection
		READ_INI_STRING(Connection,ClientIPVariable)
		READ_INI_BOOL(Connection,ChangeLogIPVariable)
		READ_INI_LIST(Connection,MonitorAddresses,INI.Cleanup)
		READ_INI_LIST(Connection,DenyAddresses,INI.Cleanup)
		READ_INI_RULE(Connection,BlockLists.Action)
		READ_INI_RULE_CACHE(Connection,RequestsLimit)
		READ_INI_LIST(Connection,ExcludedAddresses,INI.Cleanup)

		//Authentication
		READ_INI_BOOL(Authentication,NotifyAuthentication)
		READ_INI_BOOL(Authentication,ScanExcludedInstances)
		READ_INI_RULE(Authentication,BlankPasswords)
		READ_INI_RULE_LIST(Authentication,DenyDefaultPasswords,INI.Cleanup)
		READ_INI_RULE(Authentication,SamePasswordAsUsername)
		READ_INI_RULE(Authentication,SystemAccounts)
		READ_INI_RULE_CACHE(Authentication,BruteForceAttack)
		READ_INI_BOOL(Authentication,ScanAccountAllEvents)
		READ_INI_RULE_LIST(Authentication,AllowAccounts,INI.Cleanup)
		READ_INI_RULE_LIST(Authentication,DenyAccounts,INI.Cleanup)
		READ_INI_BOOL(Authentication,ScanForms)
		READ_INI_CSTRINGLIST(Authentication,UsernameFields,INI.Cleanup)
		READ_INI_CSTRINGLIST(Authentication,PasswordFields,INI.Cleanup)
		READ_INI_RULE(Authentication,FormParameterPollution)
		
		//HTTP Version
		READ_INI_RULE_INT(HTTPVersion,MaxLength)
		READ_INI_RULE_LIST(HTTPVersion,Allow,INI.CleanupUCase)

		//URL Scanning
		READ_INI_RULE(URL,RFCCompliantURL)
		READ_INI_RULE(URL,RFCCompliantHTTPURL)
		READ_INI_RULE(URL,BadParser)
		READ_INI_BOOL(URL,UseRawScan)
		READ_INI_RULE(URL,EncodingExploits)
		READ_INI_RULE(URL,ParentPath)
		READ_INI_RULE(URL,TrailingDotInDir)
		READ_INI_RULE(URL,Backslash)
		READ_INI_RULE(URL,AlternateStream)
		READ_INI_RULE(URL,Escaping)
		READ_INI_RULE(URL,MultipleCGI)
		READ_INI_RULE_INT(URL,MaxLength)
		READ_INI_RULE_CHARACTERS(URL,Characters)
		READ_INI_RULE(URL,HighBitShellcode)
		READ_INI_RULE(URL,SpecialWhitespace)
		READ_INI_RULE_LIST(URL,DenySequences,INI.CleanupLCase)
		READ_INI_RULE_MAP(URL,DenyRegex,INI.Cleanup)
		READ_INI_RULE_LIST(URL,Allow,INI.CleanupLCase)
		READ_INI_RULE_CACHE(URL,RequestsLimit)
		READ_INI_LIST(URL,ExcludedURL,INI.Cleanup)

		//Mapped Path
		READ_INI_RULE(Path,ParentPath)
		READ_INI_RULE(Path,SpecialWhitespace)
		READ_INI_RULE(Path,Escaping)
		READ_INI_RULE(Path,Dot)
		READ_INI_RULE(Path,MultipleColons)
		READ_INI_RULE_CHARACTERS(Path,Characters)
		READ_INI_RULE_LIST(Path,AllowPaths,INI.CleanupLCase)
		
		//Requested File
		READ_INI_BOOL(Filename,UseRawScan)
		READ_INI_RULE_CHARACTERS(Filename,Characters)
		READ_INI_RULE(Filename,DefaultDocument)
		READ_INI_RULE_LIST(Filename,Deny,INI.CleanupLCase)
		READ_INI_LIST(Filename,Monitor,INI.CleanupLCase)
		
		//Requested Extension
		READ_INI_RULE_LIST(Extensions,Allow,INI.CleanupLCase)
		READ_INI_RULE_LIST(Extensions,Deny,INI.CleanupLCase)
		if(!IsInList("",Extensions.Allow.List))
			Extensions.Allow.List.AddHead(""); //always allow default document
		READ_INI_RULE_CACHE(Extensions,RequestsLimit)
		READ_INI_CSTRINGLIST(Extensions,LimitExtensions,INI.CleanupLCase)
		
		//HTTP Headers
		READ_INI_RULE(Headers,SQLInjection)
		READ_INI_RULE(Headers,EncodingExploits)
		READ_INI_RULE(Headers,DirectoryTraversal)
		READ_INI_RULE(Headers,HighBitShellcode)
		READ_INI_RULE_INT(Headers,MaxLength)
		READ_INI_RULE_MAP(Headers,MaxHeaders,INI.Cleanup)		//BUG: SETTINGS - Add ':' to header name
		READ_INI_RULE_LIST(Headers,DenyHeaders,INI.Cleanup)
		READ_INI_RULE_LIST(Headers,DenySequences,INI.CleanupLCase)
		READ_INI_RULE_MAP(Headers,DenyRegex,INI.Cleanup)

		//HOST
		READ_INI_RULE(Host,RFCCompliant)
		READ_INI_RULE_LIST(Host,AllowHosts,INI.Cleanup)
		READ_INI_RULE_LIST(Host,DenyHosts,INI.CleanupLCase)
		READ_INI_LIST(Host,AllowDenyHostsAccess,INI.Cleanup)
		READ_INI_LIST(Host,Excluded,INI.Cleanup)

		//CONTENTTYPE
		READ_INI_RULE_LIST(ContentType,Allow,INI.Cleanup)
		if(!IsInList("",ContentType.Allow.List))
			ContentType.Allow.List.AddHead(""); //always allow no content-type
		READ_INI_RULE_LIST(ContentType,Deny,INI.Cleanup)
		READ_INI_RULE_MAP(ContentType,MaxLength,)
		READ_INI_RULE_STRING(ContentType,MaxContentLength)

		//TRANSFERENCODING
		READ_INI_RULE_LIST(TransferEncoding,Allow,INI.Cleanup)
		READ_INI_RULE_LIST(TransferEncoding,Deny,INI.Cleanup)

		//COOKIE
		READ_INI_BOOL(Cookie,HttpOnly)
		READ_INI_BOOL(Cookie,Secure)
		READ_INI_RULE(Cookie,SQLInjection)
		READ_INI_RULE(Cookie,EncodingExploits)
		READ_INI_RULE(Cookie,DirectoryTraversal)
		READ_INI_RULE(Cookie,HighBitShellcode)
		READ_INI_RULE(Cookie,SpecialWhitespace)
		READ_INI_RULE(Cookie,Parameters.Pollution)
		READ_INI_RULE_STRING(Cookie,Parameters.NameRequireRegex)
		READ_INI_RULE(Cookie,Parameters.InputValidation)
		READ_INI_RULE_INT(Cookie,MaxVariableLength)
		READ_INI_RULE_LIST(Cookie,DenySequences,INI.CleanupLCase)

		//USER-AGENT
		READ_INI_RULE(UserAgent,Empty)
		READ_INI_RULE(UserAgent,NonRFC)
		READ_INI_RULE(UserAgent,SQLInjection)
		READ_INI_RULE(UserAgent,HighBitShellcode)
		READ_INI_RULE(UserAgent,SpecialWhitespace)
		READ_INI_RULE_CHARACTERS(UserAgent,RequireCharacter)
		READ_INI_RULE_LIST(UserAgent,CurrentDate,INI.Cleanup)
		READ_INI_RULE_CACHE(UserAgent,Switching)
		READ_INI_RULE_LIST(UserAgent,DenyUserAgents,INI.Cleanup)
		READ_INI_RULE_LIST(UserAgent,DenySequences,INI.CleanupLCase)
		READ_INI_LIST(UserAgent,Excluded,INI.Cleanup)

		//REFERRER
		READ_INI_BOOL(Referrer,UseScan)
		READ_INI_RULE(Referrer,RFCCompliantURL)
		READ_INI_RULE(Referrer,RFCCompliantHTTPURL)
		READ_INI_RULE(Referrer,BadParser)
		READ_INI_RULE(Referrer,SQLInjection)
		READ_INI_RULE(Referrer,EncodingExploits)
		READ_INI_RULE(Referrer,HighBitShellcode)
		READ_INI_RULE(Referrer,SpecialWhitespace)
		READ_INI_RULE_CHARACTERS(Referrer,Characters)
		READ_INI_RULE_LIST(Referrer,Allow,INI.CleanupLCase)
		READ_INI_RULE_LIST(Referrer,Deny,)
		READ_INI_RULE_LIST(Referrer,DenySequences,INI.CleanupLCase)
		READ_INI_LIST(Referrer,Excluded,INI.Cleanup)

		//REFERRER: Hot Linking		
		READ_INI_BOOL(Referrer,HotLinking)
		READ_INI_CSTRINGLIST(Referrer,HotLinkingUrls,INI.CleanupLCase)
		READ_INI_CSTRINGLIST(Referrer,HotLinkingFileExtensions,INI.CleanupLCase)
		READ_INI_RULE_LIST(Referrer,HotLinkingAllowDomains,INI.CleanupLCase)
		READ_INI_RULE_LIST(Referrer,HotLinkingDenyDomains,INI.CleanupLCase)
		READ_INI_BOOL(Referrer,HotLinkingUseHostHeader)
		READ_INI_RULE(Referrer,HotLinkingBlankReferrer)

		//HTTP Verbs (Request Methods)
		READ_INI_RULE_LIST(Verbs,AllowVerbs,INI.Cleanup)
		READ_INI_RULE_LIST(Verbs,DenyVerbs,INI.CleanupUCase)
		READ_INI_RULE_LIST(Verbs,DenyPayload,INI.CleanupUCase)

		//SQL Injection Keywords
		READ_INI_INT(SQLi,AllowedCount)
		READ_INI_BOOL(SQLi,NormalizeWhitespace)
		READ_INI_BOOL(SQLi,ReplaceNumericWithOne)
		l = GetPrivateProfileSection("SQLi.Keywords",buf,sz,fn); //BUG: does not read ";" as keyword
		Split(buf,l,SQLi.Keywords);
		INI.CleanupLCase(SQLi.Keywords);

		//Encoding Exploits
		READ_INI_BOOL(EncodingExploits,ScanDoubleEncoding)
		l = GetPrivateProfileSection("EncodingExploits.Keywords",buf,sz,fn);
		Split(buf,l,EncodingExploits.Keywords);
		l = GetPrivateProfileSection("EncodingExploits.Regex",buf,sz,fn);
		CStringList eregex;
		Split(buf,l,eregex);
		EncodingExploits.Regex.RemoveAll();
		Split(eregex,'=',EncodingExploits.Regex);

		//Querystring Scanning
		READ_INI_BOOL(QueryString,UseRawScan)
		READ_INI_RULE(QueryString,SQLInjection)
		READ_INI_RULE(QueryString,EncodingExploits)
		READ_INI_RULE(QueryString,DirectoryTraversal)
		READ_INI_RULE(QueryString,HighBitShellcode)
		READ_INI_RULE(QueryString,SpecialWhitespace)
		READ_INI_RULE(QueryString,Parameters.Pollution)
		READ_INI_RULE_STRING(QueryString,Parameters.NameRequireRegex)
		READ_INI_RULE(QueryString,Parameters.InputValidation)
		READ_INI_RULE_INT(QueryString,MaxLength)
		READ_INI_RULE_INT(QueryString,MaxVariableLength)
		READ_INI_RULE_LIST(QueryString,DenySequences,INI.CleanupLCase)
		READ_INI_RULE_MAP(QueryString,DenyRegex,INI.Cleanup)
		READ_INI_LIST(QueryString,ExcludedQueryString,INI.Cleanup)

		//Global Filter Capabilities
		READ_INI_BOOL(Global,IsInstalledAsGlobalFilter)
		READ_INI_BOOL(Global,IsInstalledInWebProxy)
		READ_INI_RULE(Global,SlowHeaderAttack)
		READ_INI_RULE(Global,SlowPostAttack)

		//POST
		READ_INI_RULE(Post,RFCCompliant)
		READ_INI_RULE(Post,SQLInjection)
		READ_INI_RULE(Post,EncodingExploits)
		READ_INI_RULE(Post,DirectoryTraversal)
		READ_INI_RULE(Post,HighBitShellcode)
		READ_INI_RULE(Post,Parameters.Pollution)
		READ_INI_RULE_STRING(Post,Parameters.NameRequireRegex)
		READ_INI_RULE(Post,Parameters.InputValidation)
		READ_INI_RULE_INT(Post,MaxVariableLength)
		READ_INI_RULE_LIST(Post,DenySequences,INI.CleanupLCase)
		READ_INI_RULE_MAP(Post,DenyRegex,INI.Cleanup)
		READ_INI_INT(Post,LogLength)

		//RESPONSE MONITOR
		READ_INI_BOOL(ResponseMonitor,RemoveServerHeader)
		READ_INI_BOOL(ResponseMonitor,ChangeServerHeader)
		READ_INI_STRING(ResponseMonitor,ServerHeader)
		READ_INI_MAP(ResponseMonitor,Headers,);
		READ_INI_BOOL(ResponseMonitor,LogClientErrors)
		READ_INI_RULE_CACHE(ResponseMonitor,ClientErrors)
		READ_INI_BOOL(ResponseMonitor,LogServerErrors)
		READ_INI_RULE_CACHE(ResponseMonitor,ServerErrors)
		READ_INI_RULE_MAP(ResponseMonitor,InformationDisclosure,INI.Cleanup)

		//ADMIN
		READ_INI_BOOL(Admin,Enabled)
		READ_INI_CSTRINGLIST(Admin,FromIP,INI.Cleanup) 
		READ_INI_STRING(Admin,Login) 
		READ_INI_BOOL(Admin,AllowConfigChanges)

		return true;
	}catch(...){
		LoadDefaults();
		return false;
	}
}

bool CHTTPFirewallSettings::ParseXML(CString &key, CString &val)
{
	//if not a valid key
	if (key=="")
		return false;

	if(!CFirewallSettings::ParseXML(key,val)){

		CString name = CXML::Decode(CXML::TagName(key));

		bool done(true);

		//Scanning Engine
		PARSE_XML_BOOL(Engine,AllowLateScanning,"Allow_Late_Scanning")
		else PARSE_XML_BOOL(Engine,ScanNonSecurePort,"Scan_Non_Secure_Port")
		else PARSE_XML_BOOL(Engine,ScanSecurePort,"Scan_Secure_Port")
		else PARSE_XML_LIST(Engine,ExcludedInstances,"Excluded_Web_Instances")

		//Response Handling
		else PARSE_XML_BOOL(HTTPResponse,Directly,"Response_Directly")
		else PARSE_XML_BOOL(HTTPResponse,Redirect,"Response_Redirect")
		else PARSE_XML_STRING(HTTPResponse,RedirectURL,"Response_Redirect_URL")
		else PARSE_XML_BOOL(HTTPResponse,UseStatus,"Use_Response_Status")
		else PARSE_XML_STRING(HTTPResponse,Status,"Response_Status")
		else PARSE_XML_BOOL(HTTPResponse,DropConnection,"Response_Drop_Connection")
		else PARSE_XML_BOOL(HTTPResponse,MonitorIP,"Response_Monitor_IP")
		else PARSE_XML_INT(HTTPResponse,MonitorIPTimeout,"Response_Monitor_IP_Timeout",)
		else PARSE_XML_CACHE(HTTPResponse,BlockIP,"Response_Block_IP")

		//Logging
		else PARSE_XML_BOOL(HTTPLogging,Log_HTTP_VIA,"Log_HTTP_VIA")
		else PARSE_XML_BOOL(HTTPLogging,Log_HTTP_X_FORWARDED_FOR,"Log_HTTP_X_FORWARDED_FOR")
		else PARSE_XML_BOOL(HTTPLogging,LogHostHeader,"Log_Host_Header")
		else PARSE_XML_BOOL(HTTPLogging,LogUserAgent,"Log_User_Agent")

		//Connection
		else PARSE_XML_STRING(Connection,ClientIPVariable,"Connection_Client_IP_Variable")
		else PARSE_XML_BOOL(Connection,ChangeLogIPVariable,"Change_Log_IP_Variable")
		else PARSE_XML_LIST(Connection,MonitorAddresses,"Monitored_IP_Addresses")
		else PARSE_XML_LIST(Connection,DenyAddresses,"Denied_IP_Addresses")
		else PARSE_XML_RULE(Connection,BlockLists.Action,"Blocklists")
		else PARSE_XML_RULE_CACHE(Connection,RequestsLimit,"Connection_Requests_Limit")
		else PARSE_XML_LIST(Connection,ExcludedAddresses,"Excluded_IP_Addresses")

		//Authentication
		else PARSE_XML_BOOL(Authentication,NotifyAuthentication,"Notify_Authentication")
		else PARSE_XML_BOOL(Authentication,ScanExcludedInstances,"Scan_Authentication_Excluded_Web_Instances")
		else PARSE_XML_RULE_DENY(Authentication,BlankPasswords,"Blank_Passwords")
		else PARSE_XML_RULE_DENY(Authentication,SamePasswordAsUsername,"Same_Password_As_Username")
		else PARSE_XML_RULE_LIST_USE(Authentication,DenyDefaultPasswords,"Denied_Default_Passwords")
		else PARSE_XML_RULE_LIST(Authentication,DenyDefaultPasswords,"Default_Passwords")
		else PARSE_XML_RULE_DENY(Authentication,SystemAccounts,"System_Accounts")
		else PARSE_XML_RULE_CACHE(Authentication,BruteForceAttack,"Deny_Account_Brute_Force_Attack")//for backwards compatibility with WebKnight 3.2 and previous
		else PARSE_XML_RULE_CACHE(Authentication,BruteForceAttack,"Account_Brute_Force_Attack")
		else PARSE_XML_RULE_LIST_USE(Authentication,AllowAccounts,"Allowed_Accounts")
		else PARSE_XML_RULE_LIST_USE(Authentication,DenyAccounts,"Denied_Accounts")
		else PARSE_XML_BOOL(Authentication,ScanAccountAllEvents,"Scan_Account_All_Events")
		else PARSE_XML_BOOL(Authentication,ScanForms,"Scan_Forms_Authentication")
		else PARSE_XML_CSTRINGLIST(Authentication,UsernameFields,"Form_Username_Fields")
		else PARSE_XML_CSTRINGLIST(Authentication,PasswordFields,"Form_Password_Fields")
		else PARSE_XML_RULE(Authentication,FormParameterPollution,"Form_Parameter_Pollution")
			
		//HTTP Version
		else PARSE_XML_RULE_INT_LIMIT(HTTPVersion,MaxLength,"HTTP_Version")
		else PARSE_XML_RULE_LIST_USE(HTTPVersion,Allow,"Allowed_HTTP_Versions")

		//performance tuning
		else{	done = false;	}
		if(!done){	
		done = true;

		//URL Scanning
		PARSE_XML_RULE(URL,RFCCompliantURL,"RFC_Compliant_Url")
		else PARSE_XML_RULE(URL,RFCCompliantHTTPURL,"RFC_Compliant_HTTP_Url")
		else PARSE_XML_RULE(URL,BadParser,"Url_Bad_Parser")
		else PARSE_XML_BOOL(URL,UseRawScan,"Use_Url_Raw_Scan")
		else PARSE_XML_RULE_DENY(URL,EncodingExploits,"Url_Encoding_Exploits")
		else PARSE_XML_RULE_DENY(URL,ParentPath,"Url_Parent_Path")
		else PARSE_XML_RULE_DENY(URL,TrailingDotInDir,"Url_Trailing_Dot_In_Dir")
		else PARSE_XML_RULE_DENY(URL,Backslash,"Url_Backslash")
		else PARSE_XML_RULE_DENY(URL,AlternateStream,"Url_Alternate_Stream")
		else PARSE_XML_RULE_DENY(URL,Escaping,"Url_Escaping")
		else PARSE_XML_RULE_DENY(URL,MultipleCGI,"Url_Running_Multiple_CGI")
		else PARSE_XML_RULE_CHARACTERS_DENY(URL,Characters,"Url_Characters")
		else PARSE_XML_RULE(URL,HighBitShellcode,"Deny_Url_HighBitShellcode") //for backward compatibility with WebKnight 2.5 and previous
		else PARSE_XML_RULE_DENY(URL,HighBitShellcode,"Url_High_Bit_Shellcode")
		else PARSE_XML_RULE_DENY(URL,SpecialWhitespace,"Url_Special_Whitespace")
		else PARSE_XML_RULE_INT_LIMIT(URL,MaxLength,"Url")

		else PARSE_XML_RULE_LIST_USE(URL,DenySequences,"Denied_Url_Sequences")
		else PARSE_XML_CSTRINGLIST(URL,DenySequences.List,"URL_Denied_Sequences") //for backward compatibility with WebKnight 3.2 and previous

		else PARSE_XML_RULE_MAP(URL,DenyRegex,"Denied_Url_Regular_Expressions")

		else PARSE_XML_BOOL(URL,Allow.Action,"UseAllowedUrlStarts")		//for backward compatibility with WebKnight 1.0 & 1.1
		else PARSE_XML_RULE_LIST_USE(URL,Allow,"Allowed_Url_Starts")
		else PARSE_XML_CSTRINGLIST(URL,Allow.List,"Url_Allowed_starts")	//for backward compatibility with WebKnight 3.2 and previous
		else PARSE_XML_RULE_CACHE(URL,RequestsLimit,"Url_Requests_Limit")
		else PARSE_XML_LIST(URL,ExcludedURL,"Excluded_Urls")
				
		//Mapped Path
		else PARSE_XML_RULE_DENY(Path,ParentPath,"Parent_Path")
		else PARSE_XML_RULE_DENY(Path,SpecialWhitespace,"Special_Whitespace")
		else PARSE_XML_RULE(Path,SpecialWhitespace,"Deny_Backspace")		//for backward compatibility with WebKnight 2.5 and previous
		else PARSE_XML_RULE(Path,SpecialWhitespace,"Deny_Carriage_Return")	//for backward compatibility with WebKnight 2.5 and previous
		else PARSE_XML_RULE(Path,SpecialWhitespace,"Deny_New_Line")			//for backward compatibility with WebKnight 2.5 and previous
		else PARSE_XML_RULE_DENY(Path,Escaping,"Escaping")
		else PARSE_XML_RULE_DENY(Path,Dot,"Dot_In_Path")
		else PARSE_XML_RULE_DENY(Path,MultipleColons,"Multiple_Colons")
		else PARSE_XML_RULE_CHARACTERS_DENY(Path,Characters,"Characters")
		else PARSE_XML_RULE_LIST_USE(Path,AllowPaths,"Allowed_Paths")

		//performance tuning
		else{	done = false;	}
		if(!done){
		done = true;

		//Requested File
		PARSE_XML_BOOL(Filename,UseRawScan,"Use_Filename_Raw_Scan")
		else PARSE_XML_RULE_CHARACTERS_DENY(Filename,Characters,"Filename_Characters")
		else PARSE_XML_RULE_DENY(Filename,DefaultDocument,"Default_Document")
		else PARSE_XML_RULE_LIST_USE(Filename,Deny,"Denied_Files")
		else PARSE_XML_LIST(Filename,Monitor,"Monitored_Files")

		//Requested Extension
		else PARSE_XML_RULE_LIST_USE(Extensions,Allow,"Allowed_Extensions")
		else PARSE_XML_RULE_LIST_USE(Extensions,Deny,"Denied_Extensions")
		else PARSE_XML_RULE_CACHE(Extensions,RequestsLimit,"Extension_Requests_Limit")
		else PARSE_XML_CSTRINGLIST(Extensions,LimitExtensions,"Limit_Extensions")

		//HTTP Headers
		else PARSE_XML_RULE_DENY(Headers,SQLInjection,"Header_SQL_Injection")
		else PARSE_XML_RULE_DENY(Headers,EncodingExploits,"Header_Encoding_Exploits")
		else PARSE_XML_RULE_DENY(Headers,DirectoryTraversal,"Header_Directory_Traversal")
		else PARSE_XML_RULE_DENY(Headers,HighBitShellcode,"Header_High_Bit_Shellcode")
		else PARSE_XML_RULE_INT(Headers,MaxLength,"Maximum_Header_Length")
		else PARSE_XML_RULE_MAP(Headers,MaxHeaders,"Max_Headers")
		else PARSE_XML_RULE_LIST_USE(Headers,DenyHeaders,"Denied_Headers")
		else PARSE_XML_RULE_LIST_USE(Headers,DenySequences,"Denied_Header_Sequences")
		else PARSE_XML_RULE_MAP(Headers,DenyRegex,"Denied_Header_Regular_Expressions")

		//HOST
		else PARSE_XML_RULE(Host,RFCCompliant,"RFC_Compliant_Host_Header")
		else PARSE_XML_RULE_LIST(Host,AllowHosts,"Allowed_Host_Headers")
		else PARSE_XML_RULE_LIST(Host,DenyHosts,"Denied_Host_Headers")
		else PARSE_XML_LIST(Host,AllowDenyHostsAccess,"Allow_Denied_Host_Access")
		else PARSE_XML_LIST(Host,Excluded,"Excluded_Host_Headers")

		//CONTENTYPE
		else PARSE_XML_RULE_LIST_USE(ContentType,Allow,"Allowed_Content_Types")
		else PARSE_XML_RULE_LIST_USE(ContentType,Deny,"Deny_Content_Types") //for backwards compatibility with WebKnight 2.2
		else PARSE_XML_RULE_LIST_USE(ContentType,Deny,"Denied_Content_Types")
		else PARSE_XML_RULE_MAP(ContentType,MaxLength,"Content_Type_Max_Length")
		else PARSE_XML_RULE_STRING_LIMIT(ContentType,MaxContentLength,"Content_Length")

		//TRANSFERENCODING
		else PARSE_XML_RULE_LIST(TransferEncoding,Allow,"Allowed_Transfer_Encodings")
		else PARSE_XML_RULE_LIST(TransferEncoding,Deny,"Denied_Transfer_Encodings")

		//COOKIE
		else PARSE_XML_BOOL(Cookie,HttpOnly,"Cookie_HttpOnly")
		else PARSE_XML_BOOL(Cookie,Secure,"Cookie_Secure")
		else PARSE_XML_RULE_DENY(Cookie,SQLInjection,"Cookie_SQL_Injection")
		else PARSE_XML_RULE_DENY(Cookie,EncodingExploits,"Cookie_Encoding_Exploits")
		else PARSE_XML_RULE_DENY(Cookie,DirectoryTraversal,"Cookie_Directory_Traversal")
		else PARSE_XML_RULE_DENY(Cookie,HighBitShellcode,"Cookie_High_Bit_Shellcode")
		else PARSE_XML_RULE_DENY(Cookie,SpecialWhitespace,"Cookie_Special_Whitespace")
		else PARSE_XML_RULE(Cookie,Parameters.Pollution,"Cookie_Parameter_Pollution")
		else PARSE_XML_RULE_STRING(Cookie,Parameters.NameRequireRegex,"Cookie_Parameter_Name_Require_Regular_Expression")
		else PARSE_XML_RULE(Cookie,Parameters.InputValidation,"Cookie_Input_Validation")
		else PARSE_XML_RULE_INT_BACKWARDS(Cookie,MaxVariableLength,"Maximum_Cookie_Variable_Length")
		else PARSE_XML_RULE_LIST_USE(Cookie,DenySequences,"Denied_Cookie_Sequences")
		
		//performance tuning
		else{	done = false;	}
		if(!done){
		done = true;

		//USER-AGENT
		PARSE_XML_RULE_DENY(UserAgent,Empty,"User_Agent_Empty")
		else PARSE_XML_RULE_DENY(UserAgent,NonRFC,"User_Agent_Non_RFC")
		else PARSE_XML_RULE(UserAgent,SQLInjection,"User_Agent_SQL_Injection")
		else PARSE_XML_RULE_DENY(UserAgent,HighBitShellcode,"User_Agent_High_Bit_Shellcode")
		else PARSE_XML_RULE_DENY(UserAgent,SpecialWhitespace,"User_Agent_Special_Whitespace")
		else PARSE_XML_RULE_CHARACTERS_BACKWARDS(UserAgent,RequireCharacter,"Require_User_Agent_Character")
		else PARSE_XML_RULE_LIST(UserAgent,CurrentDate,"User_Agent_Current_Date")
		else PARSE_XML_RULE_CACHE(UserAgent,Switching,"Block_User_Agent_Switching")//for backwards compatibility with WebKnight 3.2 and previous
		else PARSE_XML_RULE_CACHE(UserAgent,Switching,"User_Agent_Switching")
		else PARSE_XML_RULE_LIST_USE(UserAgent,DenyUserAgents,"Denied_User_Agents")
		else PARSE_XML_RULE_LIST_USE(UserAgent,DenySequences,"Denied_User_Agent_Sequences")
		else PARSE_XML_LIST(UserAgent,Excluded,"Excluded_User_Agents")

		//REFERRER
		else PARSE_XML_BOOL(Referrer,UseScan,"Use_Referrer_Scanning")
		else PARSE_XML_RULE(Referrer,RFCCompliantURL,"Referrer_URL_RFC_Compliant")
		else PARSE_XML_RULE(Referrer,RFCCompliantHTTPURL,"Referrer_URL_RFC_HTTPCompliant")
		else PARSE_XML_RULE(Referrer,BadParser,"Referrer_Bad_Parser")
		else PARSE_XML_RULE_DENY(Referrer,SQLInjection,"Referrer_SQL_Injection")
		else PARSE_XML_RULE_DENY(Referrer,EncodingExploits,"Referrer_Encoding_Exploits")
		else PARSE_XML_RULE_DENY(Referrer,HighBitShellcode,"Referrer_High_Bit_Shellcode")
		else PARSE_XML_RULE_DENY(Referrer,SpecialWhitespace,"Referrer_Special_Whitespace")
		else PARSE_XML_RULE_CHARACTERS_DENY(Referrer,Characters,"Referrer_Characters")
		else PARSE_XML_RULE_LIST_USE(Referrer,Allow,"Allowed_Referrer_Starts")
		else PARSE_XML_RULE_LIST(Referrer,Deny,"Denied_Referrers")
		else PARSE_XML_RULE_LIST_USE(Referrer,DenySequences,"Deny_Referrer_Sequences") //for backwards compatibility 4.5
		else PARSE_XML_RULE_LIST(Referrer,DenySequences,"Denied_Referrer_Sequences")
		else PARSE_XML_LIST(Referrer,Excluded,"Excluded_Referrers")

		//REFERRER: Hot Linking
		else PARSE_XML_BOOL(Referrer,HotLinking,"Deny_Referrer_Hot_Linking") //for backwards compatibility 3.2
		else PARSE_XML_BOOL(Referrer,HotLinking,"Referrer_Hot_Linking")
		else PARSE_XML_CSTRINGLIST(Referrer,HotLinkingUrls,"Referrer_Hot_Linking_Urls")
		else PARSE_XML_CSTRINGLIST(Referrer,HotLinkingFileExtensions,"Referrer_Hot_Linking_File_Extensions")
		else PARSE_XML_RULE_LIST_USE(Referrer,HotLinkingAllowDomains,"Referrer_Hot_Linking_Allow_Domains")
		else PARSE_XML_RULE_LIST_USE(Referrer,HotLinkingDenyDomains,"Referrer_Hot_Linking_Deny_Domains")
		else PARSE_XML_BOOL(Referrer,HotLinkingUseHostHeader,"Referrer_Hot_Linking_Use_Host_Header")
		else PARSE_XML_RULE(Referrer,HotLinkingBlankReferrer,"Referrer_Hot_Linking_Deny_Blank_Referrer") //for backwards compatibility with WebKnight 4.0 and earlier
		else PARSE_XML_RULE(Referrer,HotLinkingBlankReferrer,"Referrer_Hot_Linking_Blank_Referrer")

		else { done = false; }
		if(!done){
			
			//HTTP Verbs (Request Methods)
			PARSE_XML_RULE_LIST_USE(Verbs,AllowVerbs,"Allowed_Verbs")
			else PARSE_XML_RULE_LIST_USE(Verbs,DenyVerbs,"Denied_Verbs")
			else PARSE_XML_RULE_LIST_USE(Verbs,DenyPayload,"Denied_Payload")

			//Querystring Scanning
			else PARSE_XML_BOOL(QueryString,UseRawScan,"Use_Querystring_Raw_Scan")
			else PARSE_XML_RULE_DENY(QueryString,SQLInjection,"Querystring_SQL_Injection")
			else PARSE_XML_RULE_DENY(QueryString,EncodingExploits,"Querystring_Encoding_Exploits")
			else PARSE_XML_RULE_DENY(QueryString,DirectoryTraversal,"Querystring_Directory_Traversal")
			else PARSE_XML_RULE_DENY(QueryString,HighBitShellcode,"Querystring_High_Bit_Shellcode")
			else PARSE_XML_RULE_DENY(QueryString,SpecialWhitespace,"Querystring_Special_Whitespace")
			else PARSE_XML_RULE(QueryString,Parameters.Pollution,"Querystring_Parameter_Pollution")
			else PARSE_XML_RULE_STRING(QueryString,Parameters.NameRequireRegex,"Querystring_Parameter_Name_Require_Regular_Expression")
			else PARSE_XML_RULE(QueryString,Parameters.InputValidation,"Querystring_Input_Validation")
			else PARSE_XML_RULE_INT_LIMIT(QueryString,MaxLength,"Querystring")
			else PARSE_XML_RULE_INT_BACKWARDS(QueryString,MaxVariableLength,"Maximum_Querystring_Variable_Length")
			else PARSE_XML_RULE_LIST_USE(QueryString,DenySequences,"Denied_Querystring_Sequences")
			else PARSE_XML_RULE_MAP(QueryString,DenyRegex,"Denied_Querystring_Regular_Expressions")
			else PARSE_XML_LIST(QueryString,ExcludedQueryString,"Excluded_Querystrings")
					
			//Global Filter Capabilities
			else PARSE_XML_BOOL(Global,IsInstalledAsGlobalFilter,"Is_Installed_As_Global_Filter")
			else PARSE_XML_BOOL(Global,IsInstalledInWebProxy,"Is_Installed_In_Web_Proxy")
			else PARSE_XML_RULE_DENY(Global,SlowHeaderAttack,"Slow_Header_Attack")
			else PARSE_XML_RULE_DENY(Global,SlowPostAttack,"Slow_Post_Attack")

			//Post
			else PARSE_XML_RULE(Post,RFCCompliant,"Post_RFC_Compliant")
			else PARSE_XML_RULE_DENY(Post,SQLInjection,"Postdata_SQL_Injection")
			else PARSE_XML_RULE_DENY(Post,EncodingExploits,"Postdata_Encoding_Exploits")
			else PARSE_XML_RULE_DENY(Post,DirectoryTraversal,"Postdata_Directory_Traversal")
			else PARSE_XML_RULE_DENY(Post,HighBitShellcode,"Postdata_High_Bit_Shellcode")
			else PARSE_XML_RULE(Post,Parameters.Pollution,"Postdata_Parameter_Pollution")
			else PARSE_XML_RULE_STRING(Post,Parameters.NameRequireRegex,"Postdata_Parameter_Name_Require_Regular_Expression")
			else PARSE_XML_RULE(Post,Parameters.InputValidation,"Postdata_Input_Validation")
			else PARSE_XML_RULE_INT_BACKWARDS(Post,MaxVariableLength,"Maximum_Postdata_Variable_Length")
			else PARSE_XML_RULE_LIST_USE(Post,DenySequences,"Denied_Post_Sequences")
			else PARSE_XML_RULE_MAP(Post,DenyRegex,"Denied_Post_Regular_Expressions")
			else PARSE_XML_INT(Post,LogLength,"Post_Log_Length",)

			//Response Monitoring
			else PARSE_XML_BOOL(ResponseMonitor,RemoveServerHeader,"Remove_Server_Header")
			else PARSE_XML_BOOL(ResponseMonitor,ChangeServerHeader,"Change_Server_Header")
			else PARSE_XML_STRING(ResponseMonitor,ServerHeader,"Server_Header")
			else PARSE_XML_MAP(ResponseMonitor,Headers,"Response_Headers")
			else PARSE_XML_BOOL(ResponseMonitor,LogClientErrors,"Log_HTTP_Client_Errors")
			else PARSE_XML_RULE_CACHE(ResponseMonitor,ClientErrors,"Block_HTTP_Client_Errors")//for backwards compatibility with WebKnight 3.2 and previous
			else PARSE_XML_RULE_CACHE(ResponseMonitor,ClientErrors,"HTTP_Client_Errors")
			else PARSE_XML_BOOL(ResponseMonitor,LogServerErrors,"Log_HTTP_Server_Errors")
			else PARSE_XML_RULE_CACHE(ResponseMonitor,ServerErrors,"Block_HTTP_Server_Errors")//for backwards compatibility with WebKnight 3.2 and previous
			else PARSE_XML_RULE_CACHE(ResponseMonitor,ServerErrors,"HTTP_Server_Errors")
			else PARSE_XML_RULE_MAP_PREFIX(ResponseMonitor,InformationDisclosure,"Information_Disclosure","Deny_")

			//ADMIN
			else PARSE_XML_BOOL(Admin,Enabled,"Admin_Enabled")
			else PARSE_XML_CSTRINGLIST(Admin,FromIP,"Admin_From_IP")
			else PARSE_XML_STRING(Admin,Login,"Admin_Login")
			else PARSE_XML_BOOL(Admin,AllowConfigChanges,"Admin_Allow_Configuration_Changes")

			//Encoding Exploits
			else PARSE_XML_BOOL(EncodingExploits,ScanDoubleEncoding,"Detect_Double_Encoding")
			else PARSE_XML_BOOL(EncodingExploits,ScanInvalidUTF8,"Detect_Invalid_UTF-8")
			else if(name.CompareNoCase("Encoding_Keywords")==0){
				XML.ToObject(val,EncodingExploits.Keywords);
			}
			else if(name.CompareNoCase("Encoding_Regular_Expressions")==0){
				XML.ToObject(val,EncodingExploits.Regex);
			}

			//SQL Injection Keywords
			else PARSE_XML_INT(SQLi,AllowedCount,"SQL_Injection_Allowed_Count",)
			else PARSE_XML_BOOL(SQLi,NormalizeWhitespace,"SQL_Injection_Normalize_Whitespace")
			else PARSE_XML_BOOL(SQLi,ReplaceNumericWithOne,"SQL_Injection_Replace_Numeric_With_One")
			else if(name.CompareNoCase("SQL_Injection_Keywords")==0){
				XML.ToObject(val,SQLi.Keywords);
			}else{
				return false; //not parsed
			}
		}
		}
		}
		}
	}
	return true;
}

bool CHTTPFirewallSettings::ApplyConstraints()
{
	//base class check
	CFirewallSettings::ApplyConstraints();

	//lowercase
	LCase(SQLi.Keywords);
	LCase(Headers.DenySequences.List);
	LCase(Post.DenySequences.List);
	LCase(URL.Allow.List);
	LCase(URL.DenySequences.List);
	LCase(Path.AllowPaths.List);
	LCase(QueryString.DenySequences.List);
	LCase(Cookie.DenySequences.List);
	LCase(Filename.Deny.List);
	LCase(Extensions.Allow.List);
	LCase(Extensions.Deny.List);
	LCase(Extensions.LimitExtensions);
	LCase(UserAgent.DenySequences.List);
	LCase(Filename.Monitor.List);

	LCase(Referrer.Allow.List);
	LCase(Referrer.DenySequences.List);
	LCase(Referrer.HotLinkingUrls);
	LCase(Referrer.HotLinkingFileExtensions);
	LCase(Referrer.HotLinkingAllowDomains.List);
	LCase(Referrer.HotLinkingDenyDomains.List);

	LCase(ContentType.Deny.List);
	LCase(TransferEncoding.Deny.List);

	//uppercase
	UCase(Verbs.DenyVerbs.List);
	UCase(Verbs.DenyPayload.List);

	return true;
}

bool CHTTPFirewallSettings::WriteToFileINI(LPCTSTR fn)
{
	/* 
	 * Write all settings to a simple INI file
	 * All checks on the file should have been
	 * done before this function is called
	 */
	try{

	//Scanning engine
	WRITE_INI_BOOL(Engine,AllowLateScanning)
	WRITE_INI_BOOL(Engine,ScanNonSecurePort)
	WRITE_INI_BOOL(Engine,ScanSecurePort)
	WRITE_INI_LIST(Engine,ExcludedInstances)

	//Response Handling
	const _HTTPResponse& Response = HTTPResponse;
	WRITE_INI_BOOL(Response,Directly)
	WRITE_INI_BOOL(Response,Redirect)
	WRITE_INI_STRING(Response,RedirectURL)
	WRITE_INI_BOOL(Response,UseStatus)
	WRITE_INI_STRING(Response,Status)
	WRITE_INI_BOOL(Response,DropConnection)
	WRITE_INI_BOOL(Response,MonitorIP)
	WRITE_INI_INT(Response,MonitorIPTimeout)
	WRITE_INI_CACHE(Response,BlockIP)

	CFirewallSettings::WriteToFileINI(fn);

	//Logging
	const _HTTPLogging& Logging = HTTPLogging;
	WRITE_INI_BOOL(Logging,Log_HTTP_VIA)
	WRITE_INI_BOOL(Logging,Log_HTTP_X_FORWARDED_FOR)
	WRITE_INI_BOOL(Logging,LogHostHeader)
	WRITE_INI_BOOL(Logging,LogUserAgent)

	//Connection control
	WRITE_INI_STRING(Connection,ClientIPVariable)
	WRITE_INI_BOOL(Connection,ChangeLogIPVariable)
	WRITE_INI_LIST(Connection,MonitorAddresses)
	WRITE_INI_LIST(Connection,DenyAddresses)
	WRITE_INI_RULE(Connection,BlockLists.Action)
	WRITE_INI_RULE_CACHE(Connection,RequestsLimit)
	WRITE_INI_LIST(Connection,ExcludedAddresses)
	
	//Authentication
	WRITE_INI_BOOL(Authentication,NotifyAuthentication)
	WRITE_INI_BOOL(Authentication,ScanExcludedInstances)
	WRITE_INI_RULE(Authentication,BlankPasswords)
	WRITE_INI_RULE(Authentication,SamePasswordAsUsername)
	WRITE_INI_RULE_LIST(Authentication,DenyDefaultPasswords)
	WRITE_INI_RULE(Authentication,SystemAccounts)
	WRITE_INI_RULE_CACHE(Authentication,BruteForceAttack)
	WRITE_INI_BOOL(Authentication,ScanAccountAllEvents)
	WRITE_INI_RULE_LIST(Authentication,AllowAccounts)
	WRITE_INI_RULE_LIST(Authentication,DenyAccounts)
	WRITE_INI_BOOL(Authentication,ScanForms)
	WRITE_INI_CSTRINGLIST(Authentication,UsernameFields)
	WRITE_INI_CSTRINGLIST(Authentication,PasswordFields)
	WRITE_INI_RULE(Authentication,FormParameterPollution)

	//HTTP Version
	WRITE_INI_RULE_INT(HTTPVersion,MaxLength)
	WRITE_INI_RULE_LIST(HTTPVersion,Allow)

	//URL
	WRITE_INI_RULE(URL,RFCCompliantURL)
	WRITE_INI_RULE(URL,RFCCompliantHTTPURL)
	WRITE_INI_RULE(URL,BadParser)
	WRITE_INI_BOOL(URL,UseRawScan)
	WRITE_INI_RULE(URL,EncodingExploits)
	WRITE_INI_RULE(URL,ParentPath)
	WRITE_INI_RULE(URL,TrailingDotInDir)
	WRITE_INI_RULE(URL,Backslash)
	WRITE_INI_RULE(URL,AlternateStream)
	WRITE_INI_RULE(URL,Escaping)
	WRITE_INI_RULE(URL,MultipleCGI)
	WRITE_INI_RULE_INT(URL,MaxLength)
	WRITE_INI_RULE_CHARACTERS(URL,Characters)
	WRITE_INI_RULE(URL,HighBitShellcode)
	WRITE_INI_RULE(URL,SpecialWhitespace)
	WRITE_INI_RULE_LIST(URL,DenySequences)
	WRITE_INI_RULE_MAP(URL,DenyRegex)
	WRITE_INI_RULE_LIST(URL,Allow)
	WRITE_INI_RULE_CACHE(URL,RequestsLimit)
	WRITE_INI_LIST(URL,ExcludedURL)

	//PATH
	WRITE_INI_RULE(Path,ParentPath)
	WRITE_INI_RULE(Path,SpecialWhitespace)
	WRITE_INI_RULE(Path,Escaping)
	WRITE_INI_RULE(Path,Dot)
	WRITE_INI_RULE(Path,MultipleColons)
	WRITE_INI_RULE_CHARACTERS(Path,Characters)
	WRITE_INI_RULE_LIST(Path,AllowPaths)

	//FILENAME
	WRITE_INI_BOOL(Filename,UseRawScan)
	WRITE_INI_RULE_CHARACTERS(Filename,Characters)
	WRITE_INI_RULE(Filename,DefaultDocument)
	WRITE_INI_RULE_LIST(Filename,Deny)
	WRITE_INI_LIST(Filename,Monitor)
		
	//EXTENSION
	WRITE_INI_RULE_LIST(Extensions,Allow)
	WRITE_INI_RULE_LIST(Extensions,Deny)
	WRITE_INI_RULE_CACHE(Extensions,RequestsLimit)
	WRITE_INI_CSTRINGLIST(Extensions,LimitExtensions)

	//HEADERS
	WRITE_INI_RULE(Headers,SQLInjection)
	WRITE_INI_RULE(Headers,EncodingExploits)
	WRITE_INI_RULE(Headers,DirectoryTraversal)
	WRITE_INI_RULE(Headers,HighBitShellcode)
	WRITE_INI_RULE_INT(Headers,MaxLength)
	WRITE_INI_RULE_MAP(Headers,MaxHeaders)
	WRITE_INI_RULE_LIST(Headers,DenyHeaders)
	WRITE_INI_RULE_LIST(Headers,DenySequences)
	WRITE_INI_RULE_MAP(Headers,DenyRegex)

	//HOST
	WRITE_INI_RULE(Host,RFCCompliant)
	WRITE_INI_RULE_LIST(Host,AllowHosts)
	WRITE_INI_RULE_LIST(Host,DenyHosts)
	WRITE_INI_LIST(Host,AllowDenyHostsAccess)
	WRITE_INI_LIST(Host,Excluded)

	//CONTENTTYPE
	WRITE_INI_RULE_LIST(ContentType,Allow)
	WRITE_INI_RULE_LIST(ContentType,Deny)
	WRITE_INI_RULE_MAP(ContentType,MaxLength)
	WRITE_INI_RULE_STRING(ContentType,MaxContentLength)

	//TRANSFERENCODING
	WRITE_INI_RULE_LIST(TransferEncoding,Allow)
	WRITE_INI_RULE_LIST(TransferEncoding,Deny)

	//COOKIE
	WRITE_INI_BOOL(Cookie,HttpOnly)
	WRITE_INI_BOOL(Cookie,Secure)
	WRITE_INI_RULE(Cookie,SQLInjection)
	WRITE_INI_RULE(Cookie,EncodingExploits)
	WRITE_INI_RULE(Cookie,DirectoryTraversal)
	WRITE_INI_RULE(Cookie,HighBitShellcode)
	WRITE_INI_RULE(Cookie,SpecialWhitespace)
	WRITE_INI_RULE(Cookie,Parameters.Pollution)
	WRITE_INI_RULE_STRING(Cookie,Parameters.NameRequireRegex)
	WRITE_INI_RULE(Cookie,Parameters.InputValidation)
	WRITE_INI_RULE_INT(Cookie,MaxVariableLength)
	WRITE_INI_RULE_LIST(Cookie,DenySequences)

	//USER-AGENT
	WRITE_INI_RULE(UserAgent,Empty)
	WRITE_INI_RULE(UserAgent,NonRFC)
	WRITE_INI_RULE(UserAgent,SQLInjection)
	WRITE_INI_RULE(UserAgent,HighBitShellcode)
	WRITE_INI_RULE(UserAgent,SpecialWhitespace)
	WRITE_INI_RULE_CHARACTERS(UserAgent,RequireCharacter)
	WRITE_INI_RULE_LIST(UserAgent,CurrentDate)
	WRITE_INI_RULE_CACHE(UserAgent,Switching)
	WRITE_INI_RULE_LIST(UserAgent,DenyUserAgents)
	WRITE_INI_RULE_LIST(UserAgent,DenySequences)
	WRITE_INI_LIST(UserAgent,Excluded)

	//REFERRER
	WRITE_INI_BOOL(Referrer,UseScan)
	WRITE_INI_RULE(Referrer,RFCCompliantURL)
	WRITE_INI_RULE(Referrer,RFCCompliantHTTPURL)
	WRITE_INI_RULE(Referrer,BadParser)
	WRITE_INI_RULE(Referrer,SQLInjection)
	WRITE_INI_RULE(Referrer,EncodingExploits)
	WRITE_INI_RULE(Referrer,HighBitShellcode)
	WRITE_INI_RULE(Referrer,SpecialWhitespace)
	WRITE_INI_RULE_CHARACTERS(Referrer,Characters)
	WRITE_INI_RULE_LIST(Referrer,Allow)
	WRITE_INI_RULE_LIST(Referrer,Deny)
	WRITE_INI_RULE_LIST(Referrer,DenySequences)
	WRITE_INI_LIST(Referrer,Excluded)

	//REFERRER: Hot Linking
	WRITE_INI_BOOL(Referrer,HotLinking)
	WRITE_INI_CSTRINGLIST(Referrer,HotLinkingUrls)
	WRITE_INI_CSTRINGLIST(Referrer,HotLinkingFileExtensions)
	WRITE_INI_RULE_LIST(Referrer,HotLinkingAllowDomains)
	WRITE_INI_RULE_LIST(Referrer,HotLinkingDenyDomains)
	WRITE_INI_BOOL(Referrer,HotLinkingUseHostHeader)
	WRITE_INI_RULE(Referrer,HotLinkingBlankReferrer)

	//VERBS
	WRITE_INI_RULE_LIST(Verbs,AllowVerbs)
	WRITE_INI_RULE_LIST(Verbs,DenyVerbs)
	WRITE_INI_RULE_LIST(Verbs,DenyPayload)

	//SQL Injection
	WRITE_INI_INT(SQLi,AllowedCount)
	WRITE_INI_BOOL(SQLi,NormalizeWhitespace)
	WRITE_INI_BOOL(SQLi,ReplaceNumericWithOne)
	WritePrivateProfileSection("SQLi.Keywords",INI.ToString(SQLi.Keywords),fn);

	//ENCODING EXPLOITS
	WRITE_INI_BOOL(EncodingExploits,ScanDoubleEncoding)
	WritePrivateProfileSection("EncodingExploits.Keywords",INI.ToString(EncodingExploits.Keywords),fn);
	WritePrivateProfileSection("EncodingExploits.Regex",INI.ToString(EncodingExploits.Regex),fn);
	
	//QUERYSTRING
	WRITE_INI_BOOL(QueryString,UseRawScan)
	WRITE_INI_RULE(QueryString,SQLInjection)
	WRITE_INI_RULE(QueryString,EncodingExploits)
	WRITE_INI_RULE(QueryString,DirectoryTraversal)
	WRITE_INI_RULE(QueryString,HighBitShellcode)
	WRITE_INI_RULE(QueryString,SpecialWhitespace)
	WRITE_INI_RULE_INT(QueryString,MaxLength)
	WRITE_INI_RULE(QueryString,Parameters.Pollution)
	WRITE_INI_RULE_STRING(QueryString,Parameters.NameRequireRegex)
	WRITE_INI_RULE(QueryString,Parameters.InputValidation)
	WRITE_INI_RULE_INT(QueryString,MaxVariableLength)
	WRITE_INI_RULE_LIST(QueryString,DenySequences)
	WRITE_INI_RULE_MAP(QueryString,DenyRegex)
	WRITE_INI_LIST(QueryString,ExcludedQueryString)
	
	//Global Filter Capabilities
	WRITE_INI_BOOL(Global,IsInstalledAsGlobalFilter)
	WRITE_INI_BOOL(Global,IsInstalledInWebProxy)
	WRITE_INI_RULE(Global,SlowHeaderAttack)
	WRITE_INI_RULE(Global,SlowPostAttack)

	//Post
	WRITE_INI_RULE(Post,RFCCompliant)
	WRITE_INI_RULE(Post,SQLInjection)
	WRITE_INI_RULE(Post,EncodingExploits)
	WRITE_INI_RULE(Post,DirectoryTraversal)
	WRITE_INI_RULE(Post,HighBitShellcode)
	WRITE_INI_RULE(Post,Parameters.Pollution)
	WRITE_INI_RULE_STRING(Post,Parameters.NameRequireRegex)
	WRITE_INI_RULE(Post,Parameters.InputValidation)
	WRITE_INI_RULE_INT(Post,MaxVariableLength)
	WRITE_INI_RULE_LIST(Post,DenySequences)
	WRITE_INI_RULE_MAP(Post,DenyRegex)
	WRITE_INI_INT(Post,LogLength)

	//RESPONSE MONITOR
	//WRITE_INI_BOOL(ResponseMonitor,RemoveServerHeader)
	//WRITE_INI_BOOL(ResponseMonitor,ChangeServerHeader)
	//WRITE_INI_STRING(ResponseMonitor,ServerHeader)
	WRITE_INI_MAP(ResponseMonitor,Headers)
	WRITE_INI_BOOL(ResponseMonitor,LogClientErrors)
	WRITE_INI_RULE_CACHE(ResponseMonitor,ClientErrors)
	WRITE_INI_BOOL(ResponseMonitor,LogServerErrors)
	WRITE_INI_RULE_CACHE(ResponseMonitor,ServerErrors)
	WRITE_INI_RULE_MAP(ResponseMonitor,InformationDisclosure)

	//ADMIN
	WRITE_INI_BOOL(Admin,Enabled)
	WRITE_INI_CSTRINGLIST(Admin,FromIP) 
	WRITE_INI_STRING(Admin,Login) 
	WRITE_INI_BOOL(Admin,AllowConfigChanges)

		return true;
	}catch(...){
		return false;
	}
}

bool CHTTPFirewallSettings::WriteToFileXML(LPCTSTR fn)
{
	CString xml("");

	//xml += "<!DOCTYPE CISAPIFilter[\r\n";			//start dtd
	//xml += "<!ELEMENT CHTTPFirewallSettings ANY >\r\n";
	//xml += " ]>\r\n";							//end dtd

	xml += "<CHTTPFirewallSettings>\r\n";	//start entity
	xml += "<AQTRONIX_CHTTPFirewallSettings App='Title'/>\r\n";
	xml += ToXML();
	xml += "</CHTTPFirewallSettings>\r\n";		//end entity

	return XML.WriteEntityToFile(fn,xml);
}

CString CHTTPFirewallSettings::GetXMLAdmin(CHTTPFirewallSettings& d)
{
	CString xml("");
	//ADMIN
	xml += XML.AddSeparator("Admin");
	WRITE_XML_BOOL(Admin,Enabled,"Admin_Enabled","Enable the built-in admin web interface: " + Admin.Url)
	WRITE_XML_CSTRINGLIST(Admin,FromIP,"Admin_From_IP","The IP addresses or ranges allowed access to the built-in admin interface.")
	WRITE_XML_STRING(Admin,Login,"Admin_Login","The login required to access the built-in admin interface. Format is username:password")
	WRITE_XML_BOOL(Admin,AllowConfigChanges,"Admin_Allow_Configuration_Changes","Allow the built-in admin web interface to make changes to the configuration (IUSR needs to have change permission on the configuration files). If disabled the admin will be a reporting utility only, no changes to the configuration files will be possible (you can also remove IUSR access). This feature requires ASP classic to be installed.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLScanningEngine(CHTTPFirewallSettings& d)
{
	CString xml("");
	//Scanning engine
	xml += XML.AddSeparator("Scanning_Engine");
	WRITE_XML_BOOL(Engine,AllowLateScanning,"Allow_Late_Scanning","This will run the filter as a low priority filter instead of high priority. Recommended is high priority (is more secure as it precedes other ISAPI filters which might have potential buffer overflows, etc.).\r\nRequires restart of IIS!")
	WRITE_XML_BOOL(Engine,ScanNonSecurePort,"Scan_Non_Secure_Port","Scan unencrypted (HTTP) web traffic (default port 80, but can be anything else).\r\nRequires restart of IIS!")
	WRITE_XML_BOOL(Engine,ScanSecurePort,"Scan_Secure_Port","Scan encrypted (HTTPS) web traffic (default port 443, but can be anything else).\r\nRequires restart of IIS!")
	WRITE_XML_LIST(Engine,ExcludedInstances,"Excluded_Web_Instances","","These are the web instances excluded from scanning. Examples are Outlook Web Access web sites (starting at site instance 100).")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLResponseHandling(CHTTPFirewallSettings& d)
{
	CString xml("");
	//Response Handling
	xml += XML.AddSeparator("Incident_Response_Handling");
	WRITE_XML_BOOL(HTTPResponse,Directly,"Response_Directly","If an attack is detected, send an immediate response to the client with a standard message. The message sent back is the contents of the denied.htm file (in the directory of the firewall)")
	WRITE_XML_BOOL(HTTPResponse,Redirect,"Response_Redirect","If an attack is detected, redirect the client to a custom url (the url specified in 'Response Redirect URL').")
	WRITE_XML_STRING(HTTPResponse,RedirectURL,"Response_Redirect_URL","This is the URL the client is redirected to if 'Response Redirect' is chosen and 'Response Directly' is disabled. This can be an absolute URL (like \"http://www.aqtronix.com\") or a relative one (like \"/denied.htm\").")
	WRITE_XML_BOOL(HTTPResponse,UseStatus,"Use_Response_Status","Whenever an attack is detected, use the value in 'Response Status' as the HTTP response status that will be sent back to the client. This only works if you don't redirect the client to a custom URL.")
	WRITE_XML_STRING(HTTPResponse,Status,"Response_Status","This is the HTTP response status like '31337 No Hacking' or '404 Object Not Found' that is sent back to the client when an attack is detected.")
	WRITE_XML_BOOL(HTTPResponse,DropConnection,"Response_Drop_Connection","Whenever an attack is detected, drop the existing connection (even if keep-alive was requested).")
	WRITE_XML_BOOL(HTTPResponse,MonitorIP,"Response_Monitor_IP","Monitor traffic coming from that IP address for a certain time-out period.")
	WRITE_XML_INT(HTTPResponse,MonitorIPTimeout,"Response_Monitor_IP_Timeout","The time-out (in hours) to monitor traffic coming from that IP address.")
	WRITE_XML_CACHE(HTTPResponse,BlockIP,"Response_Block_IP","Block the IP address if it generates too many alerts.","The maximum number of alerts before being blocked in a certain amount of time.","The time frame in which the alerts are counted (in hours).")
	xml += CFirewallSettings::GetXMLResponseHandling(d);
	return xml;
}

CString CHTTPFirewallSettings::GetXMLConnectionControl(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Connection control
	xml += XML.AddSeparator("Connection");
	WRITE_XML_STRING(Connection,ClientIPVariable,"Connection_Client_IP_Variable","The server variable to get the client IP address. Use this when the incoming requests are coming from a CDN/reverse proxy. Examples are: HTTP_X_FORWARDED_FOR or HTTP_TRUE_CLIENT_IP. If empty, REMOTE_ADDR is used.")
	WRITE_XML_BOOL(Connection,ChangeLogIPVariable,"Change_Log_IP_Variable","Adjust the web server log entries to reflect the IP address acquired from the custom IP variable.")
	WRITE_XML_LIST(Connection,MonitorAddresses,"Monitored_IP_Addresses","","Monitor the traffic of certain IP addresses or ranges by logging their requests. For ranges you can use wildcards ('10.*.*.*') and CIDR notation ('10.0.0.0/8') or hyphen ('10.0.0.1-10.0.0.5').")
	WRITE_XML_LIST(Connection,DenyAddresses,"Denied_IP_Addresses","","Deny access from certain IP addresses and ranges and log their requests. For ranges you can use wildcards ('10.*.*.*') and CIDR notation ('10.0.0.0/8') or hyphen ('10.0.0.1-10.0.0.5').")
	WRITE_XML_RULE(Connection,BlockLists.Action,"Blocklists","Use third-party blocklists and other lists (e.g. Tor_ip_list_EXIT.csv). Create a subfolder named 'Blocklists' and place them there and restart IIS.")
	WRITE_XML_RULE_CACHE(Connection,RequestsLimit,"Connection_Requests_Limit","Limit the number of requests an IP address can make.","The number of requests that can be made in a certain amount of time.","The time frame in which the requests are counted (in minutes).")
	WRITE_XML_LIST(Connection,ExcludedAddresses,"Excluded_IP_Addresses","","Exclude certain IP addresses or ranges. This allows certain hosts to have unfiltered access to your web services. For ranges you can use wildcards ('10.*.*.*') and CIDR notation ('10.0.0.0/8') or hyphen ('10.0.0.1-10.0.0.5').")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLAuthentication(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Authentication
	xml += XML.AddSeparator("Authentication");
	WRITE_XML_BOOL(Authentication,NotifyAuthentication,"Notify_Authentication","Register for the IIS authentication notifications. Disable for IIS 7.x running in integrated pipeline mode and global.asax issue (see KB 2605401). Requires restart of IIS!")
	WRITE_XML_BOOL(Authentication,ScanExcludedInstances,"Scan_Authentication_Excluded_Web_Instances","Also scan the excluded web instances in this event. Excluded web instances are not scanned by the firewall except for authentication attempts.")
	WRITE_XML_RULE(Authentication,BlankPasswords,"Blank_Passwords","This will block authentication attempts with blank passwords.")
	WRITE_XML_RULE(Authentication,SamePasswordAsUsername,"Same_Password_As_Username","This will block authentication attempts with passwords equal to the username.")
	WRITE_XML_RULE_LIST(Authentication,DenyDefaultPasswords,"Default_Passwords","","This will block authentication attempts with default and most used passwords.")
	WRITE_XML_RULE(Authentication,SystemAccounts,"System_Accounts","This will block authentication attempts with a system critical account (like IUSR_SERVERNAME, IWAM_SERVERNAME, SYSTEM, NETWORK SERVICE, TsInternetUser...).")
	WRITE_XML_RULE_CACHE(Authentication,BruteForceAttack,"Account_Brute_Force_Attack","This will block brute force attacks and possible account lockout Denial-of-Service. Detecting this is done by counting the authentication attempts within a certain period.","The maximum number an IP address is allowed to authenticate within a certain time frame.","The time frame (in minutes) within the number of authentication attempts are counted.")
	WRITE_XML_RULE_LIST(Authentication,AllowAccounts,"Allowed_Accounts","","Only allow authentication attempts with these accounts.")
	WRITE_XML_RULE_LIST(Authentication,DenyAccounts,"Denied_Accounts","","Block authentication attempts with these accounts.")
	WRITE_XML_BOOL(Authentication,ScanAccountAllEvents,"Scan_Account_All_Events","This will scan the used account (logged on user) in all other ISAPI events and possibly block the request if the account is not allowed to authenticate.")
	WRITE_XML_BOOL(Authentication,ScanForms,"Scan_Forms_Authentication","Scan Forms Authentication attempts. The username and password are extracted using the input field name lists. Excluded Web Instances are always ignored.")
	WRITE_XML_CSTRINGLIST(Authentication,UsernameFields,"Form_Username_Fields","The names of the input fields containing a username.")
	WRITE_XML_CSTRINGLIST(Authentication,PasswordFields,"Form_Password_Fields","The names of the input fields containing a password.")
	WRITE_XML_RULE(Authentication,FormParameterPollution,"Form_Parameter_Pollution","Prevent parameter pollution in forms used for authentication.")
	
	return xml;
}

CString CHTTPFirewallSettings::GetXMLRequestLimits(CHTTPFirewallSettings &d)
{
	CString xml("");
	//HTTP Version
	xml += XML.AddSeparator("HTTP_Version");
	WRITE_XML_RULE_INT(HTTPVersion,MaxLength,"Maximum_HTTP_Version","Limit the length of the HTTP version string. Every request to the web server involves specifying the HTTP version (like 'HTTP/1.1').")
	WRITE_XML_RULE_LIST(HTTPVersion,Allow,"Allowed_HTTP_Versions","","Only allow these HTTP versions. An empty line means you allow the HTTP version 0.9 (no http version)")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLURLScanning(CHTTPFirewallSettings &d)
{
	CString xml("");
	//URL Scanning
	xml += XML.AddSeparator("URL_Scanning");
	WRITE_XML_RULE(URL,RFCCompliantURL,"RFC_Compliant_Url","Check if the URL is RFC compliant. If it is not the request will be blocked.")
	WRITE_XML_RULE(URL,RFCCompliantHTTPURL,"RFC_Compliant_HTTP_Url","Check if the HTTP URL is RFC compliant. This will block authentication and fragments in the HTTP url (absolute URLs only).")
	WRITE_XML_RULE(URL,BadParser,"Url_Bad_Parser","Detect url parsing errors by clients.")
	WRITE_XML_BOOL(URL,UseRawScan,"Use_Url_Raw_Scan","Besides using the default scanning, also use the raw scanning capability to scan the URL before the web server decodes the URL (with built-in decoding engine).")
	WRITE_XML_RULE(URL,EncodingExploits,"Url_Encoding_Exploits","Do not allow encoding exploits (embedded encoding...) in the URL.")
	WRITE_XML_RULE(URL,ParentPath,"Url_Parent_Path","Deny parent path ('..') attempt in the requested url.")
	WRITE_XML_RULE(URL,TrailingDotInDir,"Url_Trailing_Dot_In_Dir","Deny a trailing dot in a directory name. This will block all requests with './'.")
	WRITE_XML_RULE(URL,Backslash,"Url_Backslash","Deny backward slashes ('\\') in the url.")
	WRITE_XML_RULE(URL,AlternateStream,"Url_Alternate_Stream","This will block all requests with a ':' in the url.")
	WRITE_XML_RULE(URL,Escaping,"Url_Escaping","Do not allow '%' in the url after decoding. This will block encoding exploits (embedded encoding) in the url.")
	WRITE_XML_RULE(URL,MultipleCGI,"Url_Running_Multiple_CGI","Do not allow using the ampersand ('&') in a url. This can be used to run multiple CGI applications.")
	WRITE_XML_RULE_INT(URL,MaxLength,"Maximum_Url","Limit the length of the url (more precisely everything in the url before the '?'). Certain attacks involve long urls. You should not allow urls longer than the longest path your operating system allows.")
	WRITE_XML_RULE_CHARACTERS(URL,Characters,"Url_Characters","Additional characters to block. If a requested url contains one of these, the request will be blocked.")
	WRITE_XML_RULE(URL,HighBitShellcode,"Url_High_Bit_Shellcode","Do not allow high bit shellcode (ascii>127). This will restrict the web sites to US-ASCII only and block characters not in this character set. Not recommended on non-US-English web sites. This will also block Unicode/UTF-8 and MBCS in the URL.")
	WRITE_XML_RULE(URL,SpecialWhitespace,"Url_Special_Whitespace","Do not allow carriage return, line feed, form feed, backspace and tabulator characters.")
	WRITE_XML_RULE_LIST(URL,DenySequences,"Denied_Url_Sequences","","Block the request when the url contains one or more of these sequences.")
	WRITE_XML_RULE_MAP(URL,DenyRegex,"Denied_Url_Regular_Expressions","","Block the request if the url matches one of these regular expressions. 'Key' is the name of the rule (will be logged). 'Value' is the regex pattern used to find matches (CAtlRegExp syntax).")
	WRITE_XML_RULE_LIST(URL,Allow,"Allowed_Url_Starts","","Only allow these character sequences a url may start with.")
	WRITE_XML_RULE_CACHE(URL,RequestsLimit,"Url_Requests_Limit","Limit the number of requests to a specific URL (except the root '/'). This can help in combating DDoS attacks on specific pages.","The number of requests that can be made in a certain amount of time.","The time frame in which the requests are counted (in seconds).")
	WRITE_XML_LIST(URL,ExcludedURL,"Excluded_Urls","","Ignore certain urls from scanning. Once the url is determined to be one of these urls (after OnReadRawData event), the request will not be scanned by the firewall. These urls are case sensitive and special characters need to be encoded as it would appear in the HTTP request line.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLMappedPath(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Mapped Path
	xml += XML.AddSeparator("Mapped_Path");
	WRITE_XML_RULE(Path,ParentPath,"Parent_Path","Deny parent path ('..') attempt in the mapped path.")
	WRITE_XML_RULE(Path,SpecialWhitespace,"Special_Whitespace","Do not allow carriage return, line feed, form feed, backspace and tabulator characters.")
	WRITE_XML_RULE(Path,Escaping,"Escaping","Deny encoding exploits in the mapped path by blocking '%'.")
	WRITE_XML_RULE(Path,Dot,"Dot_In_Path","Deny a dot in the path (except for the filename).")
	WRITE_XML_RULE(Path,MultipleColons,"Multiple_Colons","Deny more than 1 colon (':') in the path.")
	WRITE_XML_RULE_CHARACTERS(Path,Characters,"Characters","Deny the request if one or more of these characters are present in the mapped path.")
	WRITE_XML_RULE_LIST(Path,AllowPaths,"Allowed_Paths","","Only allow mapped paths which start with one of these.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLRequestedFile(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Requested File
	xml += XML.AddSeparator("Requested_File");
	WRITE_XML_BOOL(Filename,UseRawScan,"Use_Filename_Raw_Scan","Besides using the default scanning, also use the raw scanning capability to scan the requested file before the web server decodes the URL (with built-in decoding engine).")
	WRITE_XML_RULE_CHARACTERS(Filename,Characters,"Filename_Characters","Deny the request if the filename contains one of these characters.")
	WRITE_XML_RULE(Filename,DefaultDocument,"Default_Document","Deny default document requests. The client can only request a specific file, not a directory.")
	WRITE_XML_RULE_LIST(Filename,Deny,"Denied_Files","","Deny the filenames/CGI applications being accessed or run.")
	WRITE_XML_LIST(Filename,Monitor,"Monitored_Files","","Monitor access to these files.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLRequestedExtension(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Requested Extension
	WRITE_XML_RULE_LIST(Extensions,Allow,"Allowed_Extensions","","Only allow requests for files with these extensions.")
	WRITE_XML_RULE_LIST(Extensions,Deny,"Denied_Extensions","","Deny requests for files with these extensions.")
	WRITE_XML_RULE_CACHE(Extensions,RequestsLimit,"Extension_Requests_Limit","Limit the number of requests an IP address can make to certain file extensions.","The number of requests that can be made in a certain amount of time.","The time frame in which the requests are counted (in minutes).")
	WRITE_XML_CSTRINGLIST(Extensions,LimitExtensions,"Limit_Extensions","Limit the number of requests to these file extensions.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLHTTPHeaders(CHTTPFirewallSettings &d)
{
	CString xml("");
	//HTTP Headers
	xml += XML.AddSeparator("Headers");
	WRITE_XML_RULE_LIST(Headers,DenyHeaders,"Denied_Headers","","Block the request if any of these headers are present.")

	WRITE_XML_RULE(Headers,SQLInjection,"Header_SQL_Injection","Do not allow SQL injection in the headers sent to the web server.")
	WRITE_XML_RULE(Headers,EncodingExploits,"Header_Encoding_Exploits","Do not allow encoding exploits (embedded encoding...) in the headers sent to the web server.")
	WRITE_XML_RULE(Headers,DirectoryTraversal,"Header_Directory_Traversal","Do not allow directory traversal (parent path) in the headers sent to the web server. This will block any '..' preceding or following a slash ('/' or '\\').")
	WRITE_XML_RULE(Headers,HighBitShellcode,"Header_High_Bit_Shellcode","Do not allow high bit shellcode (ascii>127). This will restrict the web sites to US-ASCII only and block characters not in this character set. Not recommended for non-US-English web sites.")
	WRITE_XML_RULE_INT(Headers,MaxLength,"Maximum_Header_Length","The maximum length of a single header.")
	WRITE_XML_RULE_MAP(Headers,MaxHeaders,"Max_Headers","","Limit the length of request headers. You can specify a header and a maximum length.")
	WRITE_XML_RULE_LIST(Headers,DenySequences,"Denied_Header_Sequences","","Block the request if any of the character sequences are present in the headers.")
	WRITE_XML_RULE_MAP(Headers,DenyRegex,"Denied_Header_Regular_Expressions","","Block the request if the headers match one of these regular expressions. 'Key' is the name of the rule (will be logged). 'Value' is the regex pattern used to find matches (CAtlRegExp syntax).")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLHost(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Host
	xml += XML.AddSeparator("Host");
	WRITE_XML_RULE(Host,RFCCompliant,"RFC_Compliant_Host_Header","Block the HTTP 1.1 request if it does not include a 'Host:' header (RFC compliant).")
	WRITE_XML_RULE_LIST(Host,AllowHosts,"Allowed_Host_Headers","","Allow these hostname headers ('Host:') in requests and deny all others.")
	WRITE_XML_RULE_LIST(Host,DenyHosts,"Denied_Host_Headers","","Deny these hostname headers ('Host:') in requests.")
	WRITE_XML_LIST(Host,AllowDenyHostsAccess,"Allow_Denied_Host_Access","","Add an exclusion to the denied hostname headers by allowing access from these IP addresses. For ranges you can use wildcards ('10.*.*.*') and CIDR notation ('10.0.0.0/8') or hyphen ('10.0.0.1-10.0.0.5').")
	WRITE_XML_LIST(Host,Excluded,"Excluded_Host_Headers","","Exclude these host headers, recommended if you want to exclude scanning requests for certain web sites. Requests with these Host headers will not be scanned. Example: 'www.example.com'.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLContentType(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Content-Type
	xml += XML.AddSeparator("Content_Type");
	WRITE_XML_RULE_LIST(ContentType,Allow,"Allowed_Content_Types","","Deny the request when the Content-Type is not in this list. If for instance you want to enable all multipart types simply add 'multipart/'. This way you effectively enable 'multipart/form-data', 'multipart/mixed',...")
	WRITE_XML_RULE_LIST(ContentType,Deny,"Denied_Content_Types","","Deny the request when the Content-Type is in this list. Examples are 'application/' (will block all application content-types), 'application/octet-stream', 'application/*' , ...")
	WRITE_XML_RULE_MAP(ContentType,MaxLength,"Content_Type_Max_Length","","Block the request when it contains an entity larger than what is allowed for that content-type.")
	WRITE_XML_RULE_STRING(ContentType,MaxContentLength,"Maximum_Content_Length","Limit the value of the Content-Length header in a request. This allows you to limit the number of bytes sent to the server in requests.")
	WRITE_XML_RULE_LIST(TransferEncoding,Allow,"Allowed_Transfer_Encodings","","Deny the request when the Transfer-Encoding is not in this list.")
	WRITE_XML_RULE_LIST(TransferEncoding,Deny,"Denied_Transfer_Encodings","","Deny the request when the Transfer-Encoding is in this list.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLQuerystring(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Querystring Scanning
	xml += XML.AddSeparator("Querystring");
	WRITE_XML_BOOL(QueryString,UseRawScan,"Use_Querystring_Raw_Scan","Besides using the default scanning, also use the raw scanning capability to scan the querystring before the web server decodes the URL (with built-in decoding engine).")
	WRITE_XML_RULE(QueryString,SQLInjection,"Querystring_SQL_Injection","Do not allow SQL injection in the querystring.")
	WRITE_XML_RULE(QueryString,EncodingExploits,"Querystring_Encoding_Exploits","Do not allow encoding exploits (embedded encoding...) in the querystring.")
	WRITE_XML_RULE(QueryString,DirectoryTraversal,"Querystring_Directory_Traversal","Do not allow directory traversal in the querystring. This will block any '..' preceding or following a slash ('/' or '\\').")
	WRITE_XML_RULE(QueryString,HighBitShellcode,"Querystring_High_Bit_Shellcode","Do not allow high bit shellcode (ascii>127). This will restrict the web sites to US-ASCII only and block characters not in this character set. Not recommended for non-US-English web sites.")
	WRITE_XML_RULE(QueryString,SpecialWhitespace,"Querystring_Special_Whitespace","Do not allow carriage return, line feed, form feed, backspace and tabulator characters.")
	WRITE_XML_RULE(QueryString,Parameters.Pollution,"Querystring_Parameter_Pollution","Do not allow parameter pollution (multiple parameters with the same name).")
	WRITE_XML_RULE_STRING(QueryString,Parameters.NameRequireRegex,"Querystring_Parameter_Name_Require_Regular_Expression","Require the parameter name to match this regular expression (CAtlRegExp syntax).")
	WRITE_XML_RULE(QueryString,Parameters.InputValidation,"Querystring_Input_Validation","Validate user input. Use the admin interface to configure validators.")
	WRITE_XML_RULE_INT(QueryString,MaxLength,"Maximum_Querystring","Limit the length of the querystring (everything after the '?' in a url).")
	WRITE_XML_RULE_INT(QueryString,MaxVariableLength,"Maximum_Querystring_Variable_Length","The maximum length of a variable in the querystring.")
	WRITE_XML_RULE_LIST(QueryString,DenySequences,"Denied_Querystring_Sequences","","Block the request if any of these sequences are present in the querystring.")
	WRITE_XML_RULE_MAP(QueryString,DenyRegex,"Denied_Querystring_Regular_Expressions","","Block the request if the querystring matches one of these regular expressions. 'Key' is the name of the rule (will be logged). 'Value' is the regex pattern used to find matches (CAtlRegExp syntax).")
	WRITE_XML_LIST(QueryString,ExcludedQueryString,"Excluded_Querystrings","Ignore certain querystrings from scanning. Once the querystring is determined to be one of these querystrings (after OnReadRawData event), the request will not be scanned by the firewall. CAUTION: if attackers know these querystrings they can avoid detection!","Exclude these querystrings from being scanned. These are full querystrings, case sensitive and special characters need to be encoded as it would appear in the HTTP request line.")

	return xml;
}
CString CHTTPFirewallSettings::GetXMLPost(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Global Filter Capabilities
	xml += XML.AddSeparator("Post");
	WRITE_XML_RULE(Post,RFCCompliant,"Post_RFC_Compliant","Entities have to be accompanied by a content-type header and encoded correctly and have a content-length or use transfer-encoding.")
	WRITE_XML_RULE(Post,SQLInjection,"Postdata_SQL_Injection","Do not allow SQL injection in the data (e.g. postdata) sent to the web server.")
	WRITE_XML_RULE(Post,EncodingExploits,"Postdata_Encoding_Exploits","Do not allow encoding exploits (embedded encoding...) in the data (e.g. postdata) sent to the web server.")
	WRITE_XML_RULE(Post,DirectoryTraversal,"Postdata_Directory_Traversal","Do not allow directory traversal (parent path) in the data (e.g. postdata) sent to the web server. This will block any '..' preceding or following a slash ('/' or '\\').")
	WRITE_XML_RULE(Post,HighBitShellcode,"Postdata_High_Bit_Shellcode","Do not allow high bit shellcode (ascii>127). This will restrict the web sites to US-ASCII only and block characters not in this character set. Not recommended for non-US-English web sites.")
	WRITE_XML_RULE(Post,Parameters.Pollution,"Postdata_Parameter_Pollution","Do not allow parameter pollution (multiple parameters with the same name).")
	WRITE_XML_RULE_STRING(Post,Parameters.NameRequireRegex,"Postdata_Parameter_Name_Require_Regular_Expression","Require the parameter name to match this regular expression (CAtlRegExp syntax).")
	WRITE_XML_RULE(Post,Parameters.InputValidation,"Postdata_Input_Validation","Validate user input. Use the admin interface to configure validators.")
	WRITE_XML_RULE_INT(Post,MaxVariableLength,"Maximum_Postdata_Variable_Length","The maximum length of a variable in the data.")
	WRITE_XML_RULE_LIST(Post,DenySequences,"Denied_Post_Sequences","","Block the request if any of these character sequences are present in the data (i.e. postdata).")
	WRITE_XML_RULE_MAP(Post,DenyRegex,"Denied_Post_Regular_Expressions","","Block the request if the postdata matches one of these regular expressions. 'Key' is the name of the rule (will be logged). 'Value' is the regex pattern used to find matches (CAtlRegExp syntax).")
	WRITE_XML_INT(Post,LogLength,"Post_Log_Length","Log this amount of bytes of the post data when it is triggering an alert. Set this to zero to disable logging sensitive post data.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLGlobalFilterCapabilities(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Global Filter Capabilities
	xml += XML.AddSeparator("Global_Filter_Capabilities");
	WRITE_XML_BOOL(Global,IsInstalledAsGlobalFilter,"Is_Installed_As_Global_Filter","Register for the OnReadRawData event (required for scanning the Post in IIS 5). This event can only be called if the filter is installed as a global filter. If this is not the case then the filter will fail to load. For IIS 6, you need to run in IIS 5.0 Isolation mode. Use ISAPI extension instead for IIS6 (Worker Process mode) and IIS7+. Requires restart of IIS!")
	WRITE_XML_BOOL(Global,IsInstalledInWebProxy,"Is_Installed_In_Web_Proxy","Is the firewall installed in ISA Server or Forefront TMG. Requires restart!")
	WRITE_XML_RULE(Global,SlowHeaderAttack,"Slow_Header_Attack","Do not allow slow header attack. This is a DoS where headers are sent separately with long time intervals. This is only supported in ISAPI filter.")
	WRITE_XML_RULE(Global,SlowPostAttack,"Slow_Post_Attack","Do not allow slow POST attack. This is a DoS where postdata is sent in small packets with long time intervals. This is only supported in ISAPI filter.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLResponseMonitor(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Response Monitor
	xml += XML.AddSeparator("Response_Monitor");
	//WRITE_XML_BOOL(ResponseMonitor,RemoveServerHeader,"Remove_Server_Header","Remove the 'Server:' header in every response from the web server to the client. The server header is sensitive information that can be used by hackers or worms to probe for vulnerable systems or to know what they're up against.")
	//WRITE_XML_BOOL(ResponseMonitor,ChangeServerHeader,"Change_Server_Header","Instead of removing the server header, you can change it. This way you can fool hackers and worms by specifying another commercial web server in 'Server Header'. Note: 'Remove Server Header' has priority over this setting, so don't enable 'Remove Server Header' if you want to change the server header.")
	//WRITE_XML_STRING(ResponseMonitor,ServerHeader,"Server_Header","The server header sent back to the client in every response. This has to be in the form '<software>/<version>' (like 'Apache/0.8.4').")
	WRITE_XML_MAP(ResponseMonitor,Headers,"Response_Headers","","Add, change or remove headers from the HTTP response. Use an empty value to remove the header.")
	WRITE_XML_BOOL(ResponseMonitor,LogClientErrors,"Log_HTTP_Client_Errors","Log HTTP client side errors like '404 Not Found'. These errors start with a '4'.")
	WRITE_XML_RULE_CACHE(ResponseMonitor,ClientErrors,"HTTP_Client_Errors","Block the IP address if it generates too many HTTP client errors.","The maximum number of HTTP client errors that can be made in a certain amount of time.","The time frame in which the errors are counted (in minutes).")
	WRITE_XML_BOOL(ResponseMonitor,LogServerErrors,"Log_HTTP_Server_Errors","Log HTTP server side errors like '501 Not Implemented'. These errors start with a '5'.")
	WRITE_XML_RULE_CACHE(ResponseMonitor,ServerErrors,"HTTP_Server_Errors","Block the IP address if it generates too many HTTP server errors.","The maximum number of HTTP server errors that can be made in a certain amount of time.","The time frame in which the errors are counted (in minutes).")
	WRITE_XML_RULE_MAP(ResponseMonitor,InformationDisclosure,"Information_Disclosure","","Deny certain information disclosures in text sent from the webserver to the client. 'Key' is the name of the rule (will be logged). 'Value' is the regex pattern used to find matches (CAtlRegExp syntax).")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLSQLInjection(CHTTPFirewallSettings &d)
{
	CString xml("");
	//SQL Injection Keywords
	xml += XML.AddSeparator("SQL_Injection");
	xml += XML.ToXML("SQL_Injection_Keywords",SQLi.Keywords,"These are the SQL keywords for the SQL injection scanning.");
	WRITE_XML_INT(SQLi,AllowedCount,"SQL_Injection_Allowed_Count","Ignore this number of matches at most. Only trigger an alert when more keywords than this threshold are found.")
	WRITE_XML_BOOL(SQLi,NormalizeWhitespace,"SQL_Injection_Normalize_Whitespace","Removes redundant whitespace before scanning. This removes double whitespaces and spaces around parenthesis and comparison operators and adds at least one space before and after comments.")
	WRITE_XML_BOOL(SQLi,ReplaceNumericWithOne,"SQL_Injection_Replace_Numeric_With_One","Also scan with numeric and boolean values replaced with 1. This is needed for some of the keywords above.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLEncodingExploits(CHTTPFirewallSettings &d)
{
	CString xml("");
	//Encoding Exploits
	xml += XML.AddSeparator("Encoding_Exploits");
	xml += XML.ToXML("Encoding_Keywords",EncodingExploits.Keywords,"These are the keywords for detecting encoding exploits.");
	xml += XML.ToXML("Encoding_Regular_Expressions",EncodingExploits.Regex,"These are the regex patterns for detecting encoding exploits. 'Key' is the name of the rule (will be logged). 'Value' is the regex pattern used to find matches (CAtlRegExp syntax).");
	WRITE_XML_BOOL(EncodingExploits,ScanDoubleEncoding,"Detect_Double_Encoding","Scan for double encoding (= embedded encoding).")
	WRITE_XML_BOOL(EncodingExploits,ScanInvalidUTF8,"Detect_Invalid_UTF-8","Scan for invalid UTF-8 sequences. To avoid issues with non US-ASCII characters, set your response pages to UTF-8.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLHTTPVerbs(CHTTPFirewallSettings &d)
{
	CString xml("");
	//HTTP Verbs (Request Methods)
	xml += XML.AddSeparator("Methods");
	WRITE_XML_RULE_LIST(Verbs,AllowVerbs,"Allowed_Verbs","","Only allow these request methods (HTTP verbs).")
	WRITE_XML_RULE_LIST(Verbs,DenyVerbs,"Denied_Verbs","","Deny these request methods (HTTP verbs).")
	WRITE_XML_RULE_LIST(Verbs,DenyPayload,"Denied_Payload","","Deny payloads (entity body) for these request methods (HTTP verbs).These request methods are denied receiving a payload.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLLogging(CHTTPFirewallSettings &d)
{
	CString xml("");
	xml += XML.AddSeparator("Logging");
	xml += CFirewallSettings::GetXMLLogging(d);
	WRITE_XML_BOOL(HTTPLogging,Log_HTTP_VIA,"Log_HTTP_VIA","Log the 'Via:' header to have a clue where the original request came from (if the client uses 1 or more proxies). Note: you will not be able to log all used proxies (certain proxies don't have or remove this header)!")
	WRITE_XML_BOOL(HTTPLogging,Log_HTTP_X_FORWARDED_FOR,"Log_HTTP_X_FORWARDED_FOR","Log the 'X-Forwarded-For:' header. Certain proxies (like NetCache) add this header to the request which indicate the source IP address of the request.")
	WRITE_XML_BOOL(HTTPLogging,LogHostHeader,"Log_Host_Header","Log the host header. This will log the host header of the request, so you will have a clue to what web site the request was intended.")
	WRITE_XML_BOOL(HTTPLogging,LogUserAgent,"Log_User_Agent","Log the client user agent. This can indicate what software/tool is used to perform the attack. However it is not essential information for reporting an abuse.")
	return xml;
}

CString CHTTPFirewallSettings::ToXML()
{
	CString xml;
	CHTTPFirewallSettings d;
	xml += GetXMLAdmin(d);
	xml += GetXMLScanningEngine(d);
	xml += GetXMLResponseHandling(d);
	xml += GetXMLLogging(d);
	xml += GetXMLConnectionControl(d);
	xml += GetXMLAuthentication(d);
	xml += GetXMLRequestLimits(d);
	xml += GetXMLURLScanning(d);
	xml += GetXMLMappedPath(d);
	xml += GetXMLRequestedFile(d);
	xml += GetXMLRequestedExtension(d);
	xml += GetXMLHTTPHeaders(d);
	xml += GetXMLHost(d);
	xml += GetXMLContentType(d);
	xml += GetXMLCookie(d);
	xml += GetXMLUserAgent(d);
	xml += GetXMLReferrer(d);
	xml += GetXMLHotLinking(d);
	xml += GetXMLHTTPVerbs(d);
	xml += GetXMLQuerystring(d);
	xml += GetXMLPost(d);
	xml += GetXMLGlobalFilterCapabilities(d);
	xml += GetXMLResponseMonitor(d);
	xml += GetXMLSQLInjection(d);
	return xml;
}

bool CHTTPFirewallSettings::ReadFromFile(LPCTSTR fn)
{
	bool ret(false);

	//read settings file
	ret = CSettings::ReadFromFile(fn);
	//load agents settings
	LoadAgents();

	return ret;
}

void CHTTPFirewallSettings::ReadAgentsFile(LPCTSTR Path)
{
	//load database
	if(Agents.AgentList.ReadFromFile(Path)){
		LoadAgents();
	}else{
		/*
		//if database does not exist yet, make one with defaults
		if (!FileExists(Path)){
			Agents.AgentList.WriteToFile(Path);
		}//*/
	}
	//Agents.AgentList.WriteToFile("C:\\Debug\\Agents.xml");
}

CString CHTTPFirewallSettings::GetXMLCookie(CHTTPFirewallSettings &d)
{
	//Cookie
	CString xml("");
	xml += XML.AddSeparator("Cookie");
	WRITE_XML_BOOL(Cookie,HttpOnly,"Cookie_HttpOnly","Sets the HttpOnly attribute in the cookie. This prevents JavaScript from accessing the cookie.")
	WRITE_XML_BOOL(Cookie,Secure,"Cookie_Secure","Sets the Secure attribute in the cookie when the site is accessed over HTTPS. This prevents the browser from sending the cookie over non-HTTPS connections.")
	WRITE_XML_RULE(Cookie,SQLInjection,"Cookie_SQL_Injection","Deny SQL injection in the 'Cookie:' header. This can be useful if your website is using a database and you are using cookies for storing information related to the database.")
	WRITE_XML_RULE(Cookie,EncodingExploits,"Cookie_Encoding_Exploits","Do not allow encoding exploits (embedded encoding...) in cookies (in the 'Cookie:' header).")
	WRITE_XML_RULE(Cookie,DirectoryTraversal,"Cookie_Directory_Traversal","Do not allow directory traversal (parent path) in the cookie sent to the web server. This will block any '..' preceding or following a slash ('/' or '\\').")
	WRITE_XML_RULE(Cookie,HighBitShellcode,"Cookie_High_Bit_Shellcode","Do not allow high bit shellcode (ascii>127). This will restrict the web sites to US-ASCII only and block characters not in this character set. Not recommended for non-US-English web sites.")
	WRITE_XML_RULE(Cookie,SpecialWhitespace,"Cookie_Special_Whitespace","Do not allow carriage return, line feed, form feed, backspace and tabulator characters.")
	WRITE_XML_RULE(Cookie,Parameters.Pollution,"Cookie_Parameter_Pollution","Do not allow parameter pollution (multiple parameters with the same name).")
	WRITE_XML_RULE_STRING(Cookie,Parameters.NameRequireRegex,"Cookie_Parameter_Name_Require_Regular_Expression","Require the parameter name to match this regular expression (CAtlRegExp syntax).")
	WRITE_XML_RULE(Cookie,Parameters.InputValidation,"Cookie_Input_Validation","Validate user input. Use the admin interface to configure validators.")
	WRITE_XML_RULE_INT(Cookie,MaxVariableLength,"Maximum_Cookie_Variable_Length","The maximum length of a variable in the cookies.")
	WRITE_XML_RULE_LIST(Cookie,DenySequences,"Denied_Cookie_Sequences","","Block the request if any of the character sequences are present in the cookie.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLUserAgent(CHTTPFirewallSettings &d)
{
	//User-Agent
	CString xml("");
	xml += XML.AddSeparator("User_Agent");
	WRITE_XML_RULE(UserAgent,Empty,"User_Agent_Empty","Deny the request if the user agent is empty or not present.")
	WRITE_XML_RULE(UserAgent,NonRFC,"User_Agent_Non_RFC","Deny the request if the user agent is not RFC compliant.")
	WRITE_XML_RULE(UserAgent,SQLInjection,"User_Agent_SQL_Injection","Do not allow SQL injection in the user agent.")
	WRITE_XML_RULE(UserAgent,HighBitShellcode,"User_Agent_High_Bit_Shellcode","Deny high bit shell code in the user agent. This will block ASCII>127 and possibly blocking non US-ASCII web browsers user agent strings.")
	WRITE_XML_RULE(UserAgent,SpecialWhitespace,"User_Agent_Special_Whitespace","Do not allow carriage return, line feed, form feed, backspace and tabulator characters.")
	WRITE_XML_RULE_CHARACTERS(UserAgent,RequireCharacter,"Require_User_Agent_Character","Deny the request if the user agent does not contain at least one of these characters.")
	WRITE_XML_RULE_LIST(UserAgent,CurrentDate,"User_Agent_Current_Date","","Deny the request if the user agent contains the current date in one of these formats. Syntax is C++ 'strftime': A=weekday, B=month name, d=day of month, j=day of year, m=month, U=week of year, y=year(99), Y=year(9999).")
	WRITE_XML_RULE_CACHE(UserAgent,Switching,"User_Agent_Switching","Deny the request if the user agent is changing too much coming from a single IP address.","The maximum number of different user agents in a certain amount of time.","The time frame in which the user agents are counted (in minutes).")
	WRITE_XML_RULE_LIST(UserAgent,DenyUserAgents,"Denied_User_Agents","","Deny the request for these user agent strings.")
	WRITE_XML_RULE_LIST(UserAgent,DenySequences,"Denied_User_Agent_Sequences","","Deny the request if the user agent contains one of these character sequences.")
	WRITE_XML_LIST(UserAgent,Excluded,"Excluded_User_Agents","","Exclude the request from being scanned when the User-Agent header is one of these.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLReferrer(CHTTPFirewallSettings &d)
{
	//Referrer
	CString xml("");
	xml += XML.AddSeparator("Referrer");
	WRITE_XML_BOOL(Referrer,UseScan,"Use_Referrer_Scanning","Scan the referrer URL. Enabling this allows the other checks in this section.")
	WRITE_XML_RULE(Referrer,RFCCompliantURL,"Referrer_URL_RFC_Compliant","The referrer URL has to be RFC compliant.")
	WRITE_XML_RULE(Referrer,RFCCompliantHTTPURL,"Referrer_URL_RFC_HTTPCompliant","The referrer URL has to be HTTP RFC compliant (no authentication and no fragment).")
	WRITE_XML_RULE(Referrer,BadParser,"Referrer_Bad_Parser","Detect url parsing errors by clients.")
	WRITE_XML_RULE(Referrer,SQLInjection,"Referrer_SQL_Injection","Do not allow SQL injection in the referrer URL sent to the web server.")
	WRITE_XML_RULE(Referrer,EncodingExploits,"Referrer_Encoding_Exploits","Deny encoding exploits and embedded encoding in the referrer URL.")
	WRITE_XML_RULE(Referrer,HighBitShellcode,"Referrer_High_Bit_Shellcode","Deny high bit shell code in the referrer URL. This will block ASCII>127 in the referrer URL and possibly blocking non US-ASCII web sites from linking to your site.")
	WRITE_XML_RULE(Referrer,SpecialWhitespace,"Referrer_Special_Whitespace","Do not allow carriage return, line feed, form feed, backspace and tabulator characters.")
	WRITE_XML_RULE_LIST(Referrer,Allow,"Allowed_Referrer_Starts","","Only allow these character sequences a referrer url may start with.")
	WRITE_XML_RULE_CHARACTERS(Referrer,Characters,"Referrer_Characters","Deny certain characters in the referrer URL.")
	WRITE_XML_RULE_LIST(Referrer,Deny,"Denied_Referrers","","Deny certain referrer urls. This will match urls exactly.")
	WRITE_XML_RULE_LIST(Referrer,DenySequences,"Denied_Referrer_Sequences","","Deny these character sequences in the referrer URL.")
	WRITE_XML_LIST(Referrer,Excluded,"Excluded_Referrers","","Ignore certain referrer urls from scanning. This will only exclude the referrer url from being scanned, the rest of the request is still scanned. These urls are case sensitive and special characters need to be encoded as it would appear in the HTTP request.")
	return xml;
}

CString CHTTPFirewallSettings::GetXMLHotLinking(CHTTPFirewallSettings &d)
{
	//Referrer
	CString xml("");
	xml += XML.AddSeparator("Hot_Linking");
	WRITE_XML_BOOL(Referrer,HotLinking,"Referrer_Hot_Linking","Scan hot linking (also called direct linking, inline linking) to certain urls or file extensions from certain domains.")
	WRITE_XML_CSTRINGLIST(Referrer,HotLinkingUrls,"Referrer_Hot_Linking_Urls","The urls hot linking to is denied. This can also be used to prevent cross-site request forgery (CSRF) on those urls if Blank Referrer is set to blocked.")
	WRITE_XML_CSTRINGLIST(Referrer,HotLinkingFileExtensions,"Referrer_Hot_Linking_File_Extensions","The file extensions hot linking to is denied.")
	WRITE_XML_RULE_LIST(Referrer,HotLinkingAllowDomains,"Referrer_Hot_Linking_Allow_Domains","","Only allow certain domains to use hot linking. The domains (FQDN) or IP addresses that are allowed to use hot linking. You do not need to add your own domain to this list, see setting: \"Use Host Header\".")
	WRITE_XML_RULE_LIST(Referrer,HotLinkingDenyDomains,"Referrer_Hot_Linking_Deny_Domains","","Deny certain domains to use hot linking. The domains (FQDN) or IP addresses that are denied to use hot linking.")
	WRITE_XML_BOOL(Referrer,HotLinkingUseHostHeader,"Referrer_Hot_Linking_Use_Host_Header","Allow the Host header domain to use hot linking. This is allowing the local web site to refer to itself without needing to add the domain names to the allowed list above.")
	WRITE_XML_RULE(Referrer,HotLinkingBlankReferrer,"Referrer_Hot_Linking_Blank_Referrer","Deny requests with no referrer to the protected file extensions or urls. This will block some leeching tools but also some proxy servers and browsers with additional security applications that remove the referrer header.")
	return xml;
}

bool CHTTPFirewallSettings::Update(bool force)
{
	//update website parameters
	bool ret = ApplicationParameters.Update(force);

	//headers
	ret |= Headers.Validation.Update(force);

	//experimental settings
	ret |= Experimental.Update(force);

	//update blocklists
	if(force){
		//also load new blocklist files
		Connection.BlockLists.RemoveAll();
		Connection.BlockLists.Load(Admin.dll.Path + "Blocklists\\");
		ret = true;
	}else{
		//update existing blocklist files
		if(Connection.BlockLists.UpdateAll())
			ret = true;
	}

	if(Agents.AgentList.Update(force)){
		//reload main settings after agents
		if(FileStamp.FileName!=""){
			CString fn(FileStamp.FileName); //copy to keep pointer valid
			ReadFromFile(fn);				//reload settings
			return true;
		}else{
			return ret; //no filename like when defaults loaded
		}
	}else{
		ret |= CFirewallSettings::Update(force); //reload agents is actually done in ReadFromFile()
	}

	return ret;
}