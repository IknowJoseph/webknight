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
// WebKnightSettings.cpp: implementation of the CWebKnightSettings class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Globals.h"
//if you get an error on this line below, make sure to add the "Library" folder to your Visual Studio directories (Tools->Options->Directories)
#include "HTTPFirewall.h" //for defines
#include "WebKnightSettings.h"
#include "WebKnightUpgrade.h"
#include "WebApplications.h"
#include "FileName.h"
#include "ProcessHelper.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CWebKnightSettings::CWebKnightSettings()
{
	LoadDefaults(); //always load defaults (failover redundancy)
}

CWebKnightSettings::~CWebKnightSettings()
{

}

void CWebKnightSettings::LoadDefaults()
{
	LoadIISDefaults();
	CWebKnightUpgrade::Upgrade4_3(*this);
	CWebKnightUpgrade::Upgrade4_4(*this);
	CWebKnightUpgrade::Upgrade4_5(*this);
	CWebKnightUpgrade::Upgrade4_6(*this);
	//TODO: 4.7 - Upgrade
	//CWebKnightUpgrade::Upgrade4_7(*this);
#ifdef ISABUILD
	LoadISACompatibility();
#endif

#ifdef EXPERIMENTALBUILD
#pragma message("***** EXPERIMENTAL BUILD: This build includes some experimental rules *****")
	if(!CFileName::Exists(Admin.dll.Path + "Experimental.xml")){
		Experimental.Enable();
		Experimental.WriteToFile(Admin.dll.Path + "Experimental.xml");
	}
	Experimental.ReadFromFile(Admin.dll.Path + "Experimental.xml");
#endif

}

inline void CWebKnightSettings::LoadIISDefaults()
{
	/*
	 * Loads the default settings into memory
	 */

#ifdef PRIVATEBUILD
#pragma message("***** PRIVATE BUILD: This is a private personal build *****")
#endif

	//Scanning engine
	Engine.AllowLateScanning = false;			//high or low priority (true=low)
	Engine.ScanNonSecurePort = true;			//scan http requests
	Engine.ScanSecurePort = true;				//scan https requests
	Engine.IsPHP = false;

	//Scanning engine: excluded web instances. These are the web sites you
	//don't want to be scanned by this filter, because they are not normal
	//websites and use their own filter/extension to process requests.
	//Examples are Outlook Web Access, MS Proxy 2.0 (not ISA Server), SQL XML (only blocked if URL queries are enabled(SQL injection))
	Engine.ExcludedInstances.Enabled = false;
	Engine.ExcludedInstances.List.RemoveAll();
	Engine.ExcludedInstances.List.AddTail("100");	//Outlook Web Access - virtual HTTP server (custom)
	Engine.ExcludedInstances.List.AddTail("101");	//Outlook Web Access - virtual HTTP server (custom)
	Engine.ExcludedInstances.List.AddTail("102");	//Outlook Web Access - virtual HTTP server (custom)
	Engine.ExcludedInstances.List.AddTail("103");	//Outlook Web Access - virtual HTTP server (custom)
	Engine.ExcludedInstances.List.AddTail("104");	//Outlook Web Access - virtual HTTP server (custom)
	Engine.ExcludedInstances.List.AddTail("105");	//Outlook Web Access - virtual HTTP server (custom)
	//Engine.ExcludedInstances.List.AddTail("1");	//Default web site (ONLY if you are running MS Proxy 2.0 on the default instance and still want to protect other web instances)

	//Admin web interface
	Admin.Enabled = true;
	Admin.Url = APP_SERVER_URL;
	Admin.ServerHeader = APP_SERVER_HEADER;
	Admin.Version = (float)APP_VERSION;
	Admin.FromIP.RemoveAll();
	Admin.FromIP.AddTail("127.0.0.1");
	Admin.FromIP.AddTail("::1"); //0:0:0:0:0:0:0:1
	Admin.AllowConfigChanges = true;
	//Admin.Login = "admin:admin";
	Admin.Login = "";
	//get the directory of the .dll file & windows directory
	//Admin.dll = GetProcessPath(APP_NAME,true);
	Admin.dll = CProcessHelper::GetCurrentPath();//allow renaming of WebKnight.dll + AfxGetInstanceHandle() returns null (DllMain not called yet)
	Admin.Started = CTime::GetCurrentTime();

	//Response handling
	HTTPResponse.Directly = true;			//write contents of denied.htm to client directly (without redirect)
	HTTPResponse.UseStatus = true;			//if ResponseRedirect=true, then this has no effect
	//HTTPResponse.Status = "200 OK";		//to see the next step of the script kiddie (for testing only)
#ifdef PRIVATEBUILD
	HTTPResponse.Status = "404 Hack Not Found";
#else
	HTTPResponse.Status = "999 No Hacking";	//"31337 No Hacking";//"404 Object Not Found"; //maybe an invalid response will crash script kiddiots tools
#endif
	HTTPResponse.Redirect = false;			//redirect to a custom url
	HTTPResponse.RedirectURL = "/denied.htm";
	HTTPResponse.DropConnection = true;
	Response.LogOnly = false;			//if true, log only (for testing)

	HTTPResponse.MonitorIP = true;
	HTTPResponse.MonitorIPTimeout = 6;
	HTTPResponse.BlockIP.Enabled = false;
	HTTPResponse.BlockIP.MaxTime = 18;
	HTTPResponse.BlockIP.MaxCount = 10;

	//Reponse contents
	HTTPResponse.Contents = "<HTML><HEAD><TITLE>WebKnight Application Firewall Alert</TITLE></HEAD><BODY><H1>WebKnight Application Firewall Alert</H1></BODY></HTML>";
	if(!CFileName::ReadFileToString(Admin.dll.Path + "denied.htm",HTTPResponse.Contents)){
		CFileName::ReadFileToString(Admin.dll.Path + "nohack.htm",HTTPResponse.Contents);	//backward compatibility
	}

	//logging
	Logging.Enabled = true;

#ifdef SYSTEM_LOG_BUILD
	LogDirDefault = "%WINDIR%\\System32\\LogFiles\\WebKnight\\";
#else
	LogDirDefault = "<Path of WebKnight>\\LogFiles\\";
#endif

	Logging.UseGMT = true;
	Logging.PerProcess = false;			//unique logfile per process (for hosting with multiple instances of the webserver)
	Logging.PerProcessOwner = true;
	Logging.Retention = 28;				//number of days to keep log files
	Logging.FilenameFormat = "%y.%m.%d";
	Logging.LogDirectory = "";
#ifdef PRIVATEBUILD
	Logging.Retention = 3000;
#endif
	Logging.LogAllowed = false;				//log requests which are allowed
	Logging.LogClientIP = true;
	Logging.LogUserName = true;
	HTTPLogging.Log_HTTP_VIA = false;			//HTTP VIA headers (used in TRACE)
	HTTPLogging.Log_HTTP_X_FORWARDED_FOR = false;//certain ISPs use a proxy which add this header (one of those ISPs is telenet.be)
	HTTPLogging.LogHostHeader = true;
	HTTPLogging.LogUserAgent = false;			//not essential information except maybe to identify script kiddie tools

#ifdef ENABLE_ODBC
	Logging.ODBCEnabled = false;
	Logging.ODBCTable = "tblLog";
	Logging.ODBCDSN = "DSN=LogWebKnight;DATABASE=WebKnight;UID=WebKnight;PWD=WebKnight;"; //to SQL Server
	//Logging.ODBCDSN = "DSN=LogFile;UID=;PWD=;"; //to text file
	//Logging.ODBCEnabled = true;
#endif
#ifdef ENABLE_SYSLOG
	Logging.SyslogEnabled = false;
	Logging.SyslogServer = "localhost";
	Logging.SyslogPort = 514;
	Logging.SyslogPriority =  117; //(PRI: 117 = 21*8+5)
#endif

	//Connection control
	Connection.MonitorAddresses.Enabled = false;
	Connection.MonitorAddresses.List.RemoveAll();
	Connection.DenyAddresses.Enabled = false;
	Connection.DenyAddresses.List.RemoveAll();
	Connection.RequestsLimit.Action = Action::Disabled;
	Connection.RequestsLimit.MaxCount = 400;
	Connection.RequestsLimit.MaxTime = 2;
	Connection.ClientIPVariable = "";
	Connection.ChangeLogIPVariable = false;
#ifdef PRIVATEBUILD
	Connection.RequestsLimit.Action = Action::Block;
	Connection.RequestsLimit.MaxCount = 600;
	Connection.MonitorAddresses.Enabled = true;
	Connection.MonitorAddresses.List.AddTail("87.64.236.231");//bad requests
	Connection.MonitorAddresses.List.AddTail("194.150.224.102");//CoWorks
	Connection.MonitorAddresses.List.AddTail("82.146.99.119");//CoWorks
	//Connection.MonitorAddresses.List.AddTail("38.*.*.*");		//Spammers (with 'Referer' header)
	Connection.MonitorAddresses.List.AddTail("69.28.128.0/18");	//QuepasaCreep crawler (spammers)
	//Connection.MonitorAddresses.List.AddTail("72.14.192.0/18");	//Google research with FireFox/IE - fell for bad bot trap!
	//Connection.MonitorAddresses.List.AddTail("66.249.84.*");	//Google AdSense team 66.249.84.15 researched case about invalid clicks due to bad referrer
	//Connection.MonitorAddresses.List.AddTail("207.46.*.*");		//Microsoft Global (207.46.228.16 surfed to www.aqtronix.com on 15 Jan 2004)
	Connection.MonitorAddresses.List.AddTail("131.107.0.0/16");	//Microsoft (e-mail)
	//Connection.MonitorAddresses.List.AddTail("157.54.0.0/15");	//Microsoft (e-mail) + Bingbot
	//Connection.MonitorAddresses.List.AddTail("157.56.0.0/14");	//Microsoft (e-mail) + Bingbot
	Connection.MonitorAddresses.List.AddTail("157.60.0.0/16");	//Microsoft (e-mail)
	Connection.MonitorAddresses.List.AddTail("72.44.32.0/19");	//Amazon.com
#endif

	Connection.ExcludedAddresses.Enabled = false;
	Connection.ExcludedAddresses.List.RemoveAll();
#ifdef PRIVATEBUILD
	//attn: Joe McCray
	//This is a privatebuild directive for internal use only and is not used in our download on our site.
	//Not a single public IP address will ever be hardcoded in our product!
	//This class generates the default WebKnight.xml file
	/*
	//Neos/Ogone payment system
	Connection.ExcludedAddresses.Enabled = true;
	Connection.ExcludedAddresses.List.AddTail("212.23.45.96-212.23.45.111");
	Connection.ExcludedAddresses.List.AddTail("213.254.248.96-213.254.248.127");
	Connection.ExcludedAddresses.List.AddTail("212.35.124.160-212.35.124.175");
	*/
#else
	Connection.ExcludedAddresses.List.AddTail("127.0.0.0/8");
	Connection.ExcludedAddresses.List.AddTail("10.0.0.0/8");
	Connection.ExcludedAddresses.List.AddTail("172.16.0.0/12");
	Connection.ExcludedAddresses.List.AddTail("192.168.0.0/16");
	Connection.ExcludedAddresses.List.AddTail("::1");
#endif

#ifdef PRIVATEBUILD
	Connection.BlockLists.Action = Action::Block;
#else
	Connection.BlockLists.Action = Action::Disabled;
#endif
	Connection.BlockLists.Load(Admin.dll.Path + "Blocklists\\");
	
	//Authentication
	Authentication.NotifyAuthentication = true;
	Authentication.ScanExcludedInstances = true;
	Authentication.BlankPasswords = Action::Block;
	Authentication.SamePasswordAsUsername = Action::Block;
	Authentication.SystemAccounts = Action::Block;
	Authentication.BruteForceAttack.Action = Action::Block;
	Authentication.BruteForceAttack.MaxCount = 5;
	Authentication.BruteForceAttack.MaxTime = 30;
	Authentication.ScanAccountAllEvents = true;

	Authentication.ScanForms = true;
	Authentication.UsernameFields.RemoveAll();
	Authentication.UsernameFields.AddTail("Username");
	Authentication.UsernameFields.AddTail("username");
	Authentication.UsernameFields.AddTail("User");
	Authentication.UsernameFields.AddTail("user");
	Authentication.UsernameFields.AddTail("txtUsername");
	Authentication.UsernameFields.AddTail("txtusername");
	Authentication.UsernameFields.AddTail("txtUser");
	Authentication.UsernameFields.AddTail("txtuser");
	Authentication.UsernameFields.AddTail("log"); //Wordpress wp-login.php
	Authentication.PasswordFields.RemoveAll();
	Authentication.PasswordFields.AddTail("Password");
	Authentication.PasswordFields.AddTail("password");
	Authentication.PasswordFields.AddTail("Pass");
	Authentication.PasswordFields.AddTail("pass");
	Authentication.PasswordFields.AddTail("txtPassword");
	Authentication.PasswordFields.AddTail("txtpassword");
	Authentication.PasswordFields.AddTail("txtPass");
	Authentication.PasswordFields.AddTail("txtpass");
	Authentication.PasswordFields.AddTail("pwd"); //Wordpress wp-login.php
	Authentication.FormParameterPollution = Action::Block;

	//AUTH - Default passwords
	Authentication.DenyDefaultPasswords.Action = Action::Block;
	CSignatures::AuthPasswords(Authentication.DenyDefaultPasswords.List);
	
	//AUTH - Allowed accounts
	Authentication.AllowAccounts.Action = Action::Disabled;
	Authentication.AllowAccounts.List.RemoveAll();
	Authentication.AllowAccounts.List.AddTail("Administrateur");
	Authentication.AllowAccounts.List.AddTail("Administrator");
	Authentication.AllowAccounts.List.AddTail("Beheerder");

	//AUTH - Denied accounts
#ifdef PRIVATEBUILD
	Authentication.DenyAccounts.Action = Action::Block;
#else
	Authentication.DenyAccounts.Action = Action::Disabled;
#endif
	CSignatures::AuthAccounts(Authentication.DenyAccounts.List);

	//HTTP Version
	HTTPVersion.MaxLength.Action = Action::Block;
	HTTPVersion.MaxLength.Value = 8;				//max length of version string, in the form of HTTP/<major>.<minor> (e.g. HTTP/1.1) (HTTP/0.9 bug? buffer overflow?)
	HTTPVersion.Allow.Action = Action::Block;
	CSignatures::HTTPVersions(HTTPVersion.Allow.List);

	Headers.MaxHeaders.Action = Action::Block;
	Headers.MaxHeaders.Map.RemoveAll();
	Headers.MaxHeaders.Map.SetAt("Accept:","1024");				//rfc & filters REQUEST
	Headers.MaxHeaders.Map.SetAt("Accept-Charset:","1024");		//rfc			REQUEST
	Headers.MaxHeaders.Map.SetAt("Accept-Encoding:","256");		//rfc & filters REQUEST
	Headers.MaxHeaders.Map.SetAt("Accept-Language:","356");		//rfc & filters REQUEST (Accept language of Netscape/mozilla on Mac is 356 long)
	Headers.MaxHeaders.Map.SetAt("Accept-Ranges:","128");		//rfc			REQUEST/RESPONSE
	//Headers.MaxHeaders.Map.SetAt("Age:","32");				//rfc					RESPONSE
	Headers.MaxHeaders.Map.SetAt("Allow:","512");				//rfc			REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Authorization:","5120");		//rfc & filters REQUEST (Kerberos might use up to 5KB, otherwise 2.5KB is enough) 
	//Headers.MaxHeaders.Map.SetAt("Authentication-Info:","4000");//rfc2069				RESPONSE
	Headers.MaxHeaders.Map.SetAt("BITS-Packet-Type:","64");				//BITS upload REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("BITS-Protocol:","1024");				//BITS upload		  RESPONSE
	Headers.MaxHeaders.Map.SetAt("BITS-Session-Id:","1024");				//BITS upload REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("BITS-Supported-Protocols:","4095");	//BITS upload REQUEST
	//Headers.MaxHeaders.Map.SetAt("BITS-Host-Id:","256");				//BITS upload		  RESPONSE
	//Headers.MaxHeaders.Map.SetAt("BITS-Host-Id-Fallback-Timeout:","20");//BITS upload		  RESPONSE
	//Headers.MaxHeaders.Map.SetAt("BITS-Received-Content-Range:","20");	//BITS upload		  RESPONSE
	//Headers.MaxHeaders.Map.SetAt("BITS-Reply-URL:","1024");				//BITS upload		  RESPONSE
	//Headers.MaxHeaders.Map.SetAt("BITS-Error-Code:","64");				//BITS upload		  RESPONSE
	//Headers.MaxHeaders.Map.SetAt("BITS-Error-Context:","64");			//BITS upload		  RESPONSE
	Headers.MaxHeaders.Map.SetAt("BITS-Original-Request-URL:","1024");		//BITS Notification REQUEST
	Headers.MaxHeaders.Map.SetAt("BITS-Request-DataFile-Name:","1024");	//BITS Notification REQUEST
	Headers.MaxHeaders.Map.SetAt("BITS-Response-DataFile-Name:","1024");	//BITS Notification REQUEST
	//Headers.MaxHeaders.Map.SetAt("BITS-Static-Response-URL:","1024");		//BITS Notification			RESPONSE
	//Headers.MaxHeaders.Map.SetAt("BITS-Copy-File-To-Destination:","64");	//BITS Notification			RESPONSE
	Headers.MaxHeaders.Map.SetAt("Cache-Control:","256");		//rfc			REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Charge-To:","512");			//w3c			REQUEST
	Headers.MaxHeaders.Map.SetAt("Connection:","256");			//rfc & filters REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Content-Base:","1024");		//rfc MIME		REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Content-Description:","1000");//rfc MIME		REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Content-Disposition:","256");	//rfc MIME		REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Content-Encoding:","128");	//rfc			REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Content-Id:","1024");			//rfc MIME		REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Content-Language:","256");	//rfc			REQUEST/RESPONSE
	//Headers.MaxHeaders.Map.SetAt("Content-Length:","9");		//rfc - is checked elsewhere
	Headers.MaxHeaders.Map.SetAt("Content-Location:","1024");	//rfc			REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Content-MD5:","4000");		//rfc			REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Content-Name:","512");					//BITS REQUEST
	Headers.MaxHeaders.Map.SetAt("Content-Range:","256");		//rfc			REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Content-Transfer-Encoding:","128");//winhttp.dll	NOT ALLOWED IN HTTP
	Headers.MaxHeaders.Map.SetAt("Content-Type:","256");		//rfc			REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Cookie:","4095");				//winhttp & filters
	//Headers.MaxHeaders.Map.SetAt("Cost:","256");				//winhttp.dll			RESPONSE
	Headers.MaxHeaders.Map.SetAt("Date:","64");					//rfc			REQUEST/RESPONSE
	//Headers.MaxHeaders.Map.SetAt("DAV:","128");				//rfc 2518(DAV)			RESPONSE	(not in winhttp.dll)
	Headers.MaxHeaders.Map.SetAt("Depth:","64");				//rfc 2518(DAV)	REQUEST				(not in winhttp.dll)
	Headers.MaxHeaders.Map.SetAt("Derived-From:","9000");		//winhttp.dll	REQUEST/RESPONSE?
	Headers.MaxHeaders.Map.SetAt("Destination:","1024");		//rfc 2518(DAV)	REQUEST				(not in winhttp.dll)
	Headers.MaxHeaders.Map.SetAt("DNT:","1");					//Do-Not-Track	REQUEST
	//Headers.MaxHeaders.Map.SetAt("ETag:","4000");				//rfc					RESPONSE
	Headers.MaxHeaders.Map.SetAt("Expect:","256");				//rfc			REQUEST
	Headers.MaxHeaders.Map.SetAt("Expires:","64");				//rfc			REQUEST?/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Forwarded:","9000");			//winhttp.dll	REQUEST/RESPONSE?
	Headers.MaxHeaders.Map.SetAt("From:","321");				//rfc			REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Host:","256");				//rfc & filters REQUEST
	Headers.MaxHeaders.Map.SetAt("HTTP2-Settings:","16384");	//HTTP/2		REQUEST			multiple of 6 octets (16384 initial value)
	Headers.MaxHeaders.Map.SetAt("If:","4095");					//rfc 2518(DAV)	REQUEST
	Headers.MaxHeaders.Map.SetAt("If-Match:","256");			//rfc			REQUEST
	Headers.MaxHeaders.Map.SetAt("If-Modified-Since:","64");	//rfc & filters REQUEST
	Headers.MaxHeaders.Map.SetAt("If-None-Match:","256");		//rfc & filters REQUEST
	Headers.MaxHeaders.Map.SetAt("If-Range:","4000");			//rfc			REQUEST
	Headers.MaxHeaders.Map.SetAt("If-Unmodified-Since:","64");	//rfc			REQUEST
	//Headers.MaxHeaders.Map.SetAt("Last-Modified:","64");		//rfc					RESPONSE
	//Headers.MaxHeaders.Map.SetAt("Link:","1024");				//winhttp.dll	        RESPONSE
	//Headers.MaxHeaders.Map.SetAt("Location:","1024");			//rfc					RESPONSE
	Headers.MaxHeaders.Map.SetAt("Lock-Token:","1024");			//rfc 2518(DAV)	REQUEST
	Headers.MaxHeaders.Map.SetAt("Max-Forwards:","32");			//rfc			REQUEST
	Headers.MaxHeaders.Map.SetAt("Message-id:","1024");			//winhttp.dll	REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Mime-Version:","128");		//winhttp.dll	REQUEST?/RESPONSE? (winhttp.dll contains 1 header more than wininet.dll: "Mime-Version:")
	Headers.MaxHeaders.Map.SetAt("Ms-Echo-Reply:","128");		//winhttp.dll	REQUEST?/RESPONSE?
	Headers.MaxHeaders.Map.SetAt("Ms-Echo-Request:","128");		//winhttp.dll	REQUEST?/RESPONSE?
	Headers.MaxHeaders.Map.SetAt("Orig-Uri:","1024");			//winhttp.dll	REQUEST
	Headers.MaxHeaders.Map.SetAt("Overwrite:","64");			//rfc 2518(DAV)	REQUEST			(not in winhttp.dll)
	Headers.MaxHeaders.Map.SetAt("PassportConfig:","4000");		//winhttp.dll		TO DO: in request & value?
	Headers.MaxHeaders.Map.SetAt("PassportURLs:","4000");		//winhttp.dll		TO DO: in request & value?
	Headers.MaxHeaders.Map.SetAt("Pragma:","256");				//rfc			REQUEST/RESPONSE
	//Headers.MaxHeaders.Map.SetAt("Proxy-Authenticate:","256");//rfc					RESPONSE
	Headers.MaxHeaders.Map.SetAt("Proxy-Authorization:","4000");//rfc			REQUEST
	Headers.MaxHeaders.Map.SetAt("Proxy-Connection:","256");	//winhttp.dll	REQUEST/RESPONSE?
	Headers.MaxHeaders.Map.SetAt("Proxy-Support:","4000");		//winhttp.dll		TO DO: in request & value?
	Headers.MaxHeaders.Map.SetAt("Public:","4000");				//winhttp.dll		TO DO: in request & value?
	Headers.MaxHeaders.Map.SetAt("Range:","256");				//rfc			REQUEST/RESPONSE?
	Headers.MaxHeaders.Map.SetAt("Referer:","4095");			//rfc & filters REQUEST
	//Headers.MaxHeaders.Map.SetAt("Refresh:","64");			//winhttp.dll			RESPONSE
	//Headers.MaxHeaders.Map.SetAt("Retry-After:","64");		//rfc					RESPONSE
	//Headers.MaxHeaders.Map.SetAt("Server:","256");			//rfc					RESPONSE
	//Headers.MaxHeaders.Map.SetAt("Set-Cookie:","4095");		//winhttp.dll			RESPONSE
	Headers.MaxHeaders.Map.SetAt("SOAPAction:","4095");			//SOAP				REQUEST
	//Headers.MaxHeaders.Map.SetAt("Status-URI:","1024");		//rfc 2518(DAV)			RESPONSE (not in winhttp.dll)
	Headers.MaxHeaders.Map.SetAt("Timeout:","1024");			//rfc 2518(DAV)	REQUEST			 (not in winhttp.dll)
	Headers.MaxHeaders.Map.SetAt("Title:","9000");				//winhttp.dll	REQUEST?/RESPONSE
	Headers.MaxHeaders.Map.SetAt("TE:","128");					//rfc only!		REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Trailer:","128");				//rfc only!		REQUEST?/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Transfer-Encoding:","128");	//rfc & filters REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Translate:","256");			//winhttp.dll	REQUEST
	Headers.MaxHeaders.Map.SetAt("UA-color:","32");				//nonstandard	REQUEST
	Headers.MaxHeaders.Map.SetAt("UA-CPU:","32");				//nonstandard	REQUEST
	Headers.MaxHeaders.Map.SetAt("UA-OS:","128");				//nonstandard	REQUEST
	Headers.MaxHeaders.Map.SetAt("UA-pixels:","15");			//nonstandard	REQUEST
	Headers.MaxHeaders.Map.SetAt("UA-Voice:","5");				//nonstandard	REQUEST
	Headers.MaxHeaders.Map.SetAt("Unless-Modified-Since:","64");//winhttp.dll	REQUEST
	Headers.MaxHeaders.Map.SetAt("Upgrade:","256");				//rfc			REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Uri:","1024");				//winhttp.dll	REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("User-Agent:","320");			//rfc & filters	REQUEST
	Headers.MaxHeaders.Map.SetAt("Vary:","128");				//rfc			REQUEST?/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Via:","9000");				//rfc			REQUEST/RESPONSE
	//Headers.MaxHeaders.Map.SetAt("Warning:","4000");			//rfc					RESPONSE
	Headers.MaxHeaders.Map.SetAt("Version:","128");				//www.w3.org	REQUEST/RESPONSE
	//Headers.MaxHeaders.Map.SetAt("WWW-Authenticate:","256");	//rfc					RESPONSE
	Headers.MaxHeaders.Map.SetAt("Origin:","1024");					//CORS		REQUEST
	//Headers.MaxHeaders.Map.SetAt("Access-Control-Allow-Origin:","1024");//CORS		RESPONSE
	Headers.MaxHeaders.Map.SetAt("Sec-WebSocket-Key:","128"); 		//WebSocket	REQUEST
	Headers.MaxHeaders.Map.SetAt("Sec-WebSocket-Extensions:","256");//WebSocket	REQUEST/RESPONSE
	//Headers.MaxHeaders.Map.SetAt("Sec-WebSocket-Accept:","256");	//WebSocket			RESPONSE
	Headers.MaxHeaders.Map.SetAt("Sec-WebSocket-Protocol:","256");	//WebSocket	REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("Sec-WebSocket-Version:","32");	//WebSocket	REQUEST/RESPONSE
	Headers.MaxHeaders.Map.SetAt("X-Forwarded-For:","8190");		//			REQUEST
	//Headers.MaxHeaders.Map.SetAt("X-UA-Compatible:","64");		//MSIE 8+			RESPONSE

	//URL
	URL.EncodingExploits = Action::Block;
	URL.ParentPath = Action::Block;			//no ".." in url
	URL.TrailingDotInDir = Action::Block;	//no "./" in url
	URL.Backslash = Action::Block;			//no '\' in url
	URL.AlternateStream = Action::Disabled;	//you should allow ':' in url (see rfc 2616), urlscan blocks it, which is wrong!!!
	URL.Escaping = Action::Block;			//no '%' in url (after url normalization)
	URL.MultipleCGI = Action::Block;		//no '&' in url
	URL.Characters.Action = Action::Block;
	URL.Characters.Value = "?#;";			//other characters to block
	URL.HighBitShellcode = Action::Block;	//deny high bit shellcode (ascii>127)
	URL.SpecialWhitespace = Action::Block;
	URL.MaxLength.Action = Action::Block;
	URL.MaxLength.Value = 1024; //16384;		//max length of url (MAX_PATH=260)

	//URL: Deny certain sequences (must be lowercase)
	URL.DenySequences.Action = Action::Block;
	URL.DenySequences.List.RemoveAll();
	URL.DenySequences.List.AddTail("/scripts");		//scripts (needed by MS Proxy 2.0, frontpage - not by ISA Server)
	URL.DenySequences.List.AddTail("/iishelp");		//iishelp
	URL.DenySequences.List.AddTail("/iisadmin");	//iisadmin (remote administration)
	URL.DenySequences.List.AddTail("/msadc");		//Microsoft Advanced Data Connector = RDS (Remote Data Service)
	URL.DenySequences.List.AddTail("/printers");	//installed printers
	URL.DenySequences.List.AddTail("/samples");		//just samples
	URL.DenySequences.List.AddTail("/iisadmpwd");	//change windows password
	URL.DenySequences.List.AddTail("/_vti_aut");	//frontpage extensions
	URL.DenySequences.List.AddTail("/_vti_bin");	//frontpage extensions
	URL.DenySequences.List.AddTail("/_vti_rpc");	//frontpage extensions
	URL.DenySequences.List.AddTail("/_vti_pvt");	//frontpage extensions
	URL.DenySequences.List.AddTail("/admcgi");		//frontpage extensions
	URL.DenySequences.List.AddTail("/admisapi");	//frontpage extensions
	URL.DenySequences.List.AddTail("/_private");	//frontpage extensions
	URL.DenySequences.List.AddTail("/_vti_cnf");	//frontpage extensions
	URL.DenySequences.List.AddTail("/_vti_log");	//frontpage extensions
	URL.DenySequences.List.AddTail("/_vti_script");//frontpage extensions
	URL.DenySequences.List.AddTail("/_vti_txt");	//frontpage extensions
	URL.DenySequences.List.AddTail("/_mem_bin");	//frontpage extensions
	URL.DenySequences.List.AddTail("/ftp only");	//ftp only :)
	URL.DenySequences.List.AddTail("/ftp_only");	//ftp only :)
	URL.DenySequences.List.AddTail("/ftp-only");	//ftp only :)
	//URL.DenySequences.List.AddTail("/winnt");		//operating system sensitive dirs
	//URL.DenySequences.List.AddTail("/system");
	URL.DenySequences.List.AddTail("/system32");
	URL.DenySequences.List.AddTail("/adsamples");
	URL.DenySequences.List.AddTail("/pbserver");
	URL.DenySequences.List.AddTail("/rpc");
	URL.DenySequences.List.AddTail("/cfdocs");				//coldfusion docs
	URL.DenySequences.List.AddTail("/cfdocs/exampleapp");	//coldfusion samples
	URL.DenySequences.List.AddTail("/cfdocs/snippets");		//coldfusion samples
	URL.DenySequences.List.AddTail("/cfdocs/expeval");		//coldfusion
	URL.DenySequences.List.AddTail("/cfdocs/examples");		//coldfusion samples
	URL.DenySequences.List.AddTail("/cfappman");			//coldfusion samples
	URL.DenySequences.List.AddTail("/cfide/administrator");//coldfusion
	URL.DenySequences.List.AddTail("/siteserver");
	URL.DenySequences.List.AddTail("/advworks");
	URL.DenySequences.List.AddTail("/ssi/envout.bat");
	URL.DenySequences.List.AddTail("/cgi-bin");		//CGI
	URL.DenySequences.List.AddTail("/cgi-local");	//CGI
	URL.DenySequences.List.AddTail("/cgi-win");		//CGI
	URL.DenySequences.List.AddTail("/htbin");		//CGI
	URL.DenySequences.List.AddTail("/cgibin");		//CGI
	URL.DenySequences.List.AddTail("/cgis");		//CGI
	URL.DenySequences.List.AddTail("/cgi");			//CGI
	URL.DenySequences.List.AddTail("/test-cgi");	//CGI
	URL.DenySequences.List.AddTail("/ows-bin/");
	URL.DenySequences.List.AddTail("/bin/");
	URL.DenySequences.List.AddTail("/sbin/");		
	URL.DenySequences.List.AddTail("/etc/");
	URL.DenySequences.List.AddTail("/database/");	//database
	URL.DenySequences.List.AddTail("/databases/");	//database
	URL.DenySequences.List.AddTail("/dbase/");		//database
	URL.DenySequences.List.AddTail("/db/");			//database
	URL.DenySequences.List.AddTail("/storedb/");	//database
	URL.DenySequences.List.AddTail("/fpdb/");		//frontpage extensions (database)
	URL.DenySequences.List.AddTail("/log/");		//logs
	URL.DenySequences.List.AddTail("/logs/");
	URL.DenySequences.List.AddTail("/logfile/");
	URL.DenySequences.List.AddTail("/logfiles/");
	URL.DenySequences.List.AddTail("/logger/");
	URL.DenySequences.List.AddTail("/server_stats/");
	URL.DenySequences.List.AddTail("/trafficlog/");
	URL.DenySequences.List.AddTail("/weblog/");
	URL.DenySequences.List.AddTail("/weblogs/");
	URL.DenySequences.List.AddTail("/webstats/");
	URL.DenySequences.List.AddTail("/wstats/");
	URL.DenySequences.List.AddTail("/wusage/");
	URL.DenySequences.List.AddTail("/wwwlog/");
	URL.DenySequences.List.AddTail("/wwwstats/");
	URL.DenySequences.List.AddTail("/mall_log_files/");
	URL.DenySequences.List.AddTail("/admin");		//admin stuff
	URL.DenySequences.List.AddTail("/admin_/");
	URL.DenySequences.List.AddTail("/_admin/");
	URL.DenySequences.List.AddTail("/srchadm/");
	URL.DenySequences.List.AddTail("/admnlogin");
	URL.DenySequences.List.AddTail("/adminlogin");
	URL.DenySequences.List.AddTail("/siteadmin");
	URL.DenySequences.List.AddTail("/w3perl/admin");
	URL.DenySequences.List.AddTail("/webaccess/");
	URL.DenySequences.List.AddTail("/account/");
	URL.DenySequences.List.AddTail("/administrator/");
	URL.DenySequences.List.AddTail("/config/");
	URL.DenySequences.List.AddTail("/fpadmin/");
	URL.DenySequences.List.AddTail("/srchadm/");
	URL.DenySequences.List.AddTail("/admin_files");
	URL.DenySequences.List.AddTail("/passwords/");
	URL.DenySequences.List.AddTail("/etc/passwd");
	URL.DenySequences.List.AddTail("/exchange");	//Outlook Web Access on Default web site
	URL.DenySequences.List.AddTail("/exchweb");		//Outlook Web Access on Default web site
	URL.DenySequences.List.AddTail("/public");		//Outlook Web Access (Public folders)
	URL.DenySequences.List.AddTail("/exadmin");		//Outlook Web Access Administration
	URL.DenySequences.List.AddTail("/hit_tracker/");//counter stuff
	URL.DenySequences.List.AddTail("/hitmatic/");
	URL.DenySequences.List.AddTail("/counter/");
	URL.DenySequences.List.AddTail("/c/");			//other things
	URL.DenySequences.List.AddTail("/d/");
	URL.DenySequences.List.AddTail("/doc-html/");
	URL.DenySequences.List.AddTail("/ftp/");
	URL.DenySequences.List.AddTail("/htdocs/");
	URL.DenySequences.List.AddTail("/install/");
	URL.DenySequences.List.AddTail("/intranet/");
	URL.DenySequences.List.AddTail("/jdbc/");
	URL.DenySequences.List.AddTail("/msql/");
	URL.DenySequences.List.AddTail("/odbc/");
	URL.DenySequences.List.AddTail("/oracle/");
	URL.DenySequences.List.AddTail("/private/");
	URL.DenySequences.List.AddTail("/sql/");
	URL.DenySequences.List.AddTail("/temp/");		//temp & test stuff
	URL.DenySequences.List.AddTail("/tmp/");
	URL.DenySequences.List.AddTail("/test/");
	URL.DenySequences.List.AddTail("/webdriver");
	URL.DenySequences.List.AddTail(" /http/1.");
	URL.DenySequences.List.AddTail("/glimpse");
	URL.DenySequences.List.AddTail("/aglimpse");
	URL.DenySequences.List.AddTail("/htmlscript");
	URL.DenySequences.List.AddTail("/info2www");
	URL.DenySequences.List.AddTail("/nph-test-cgi");
	URL.DenySequences.List.AddTail("/nph-publish");
	URL.DenySequences.List.AddTail("/view-source");
	URL.DenySequences.List.AddTail("/w3-msql");
	URL.DenySequences.List.AddTail("/www-sql");
	URL.DenySequences.List.AddTail("/level/*/exec/");
	URL.DenySequences.List.AddTail("/nessus_is_probing_you_");
	URL.DenySequences.List.AddTail("/~root");
	URL.DenySequences.List.AddTail("/handler");
	URL.DenySequences.List.AddTail("/backup");
	URL.DenySequences.List.AddTail("/filemail");
	URL.DenySequences.List.AddTail("/plusmail");
	URL.DenySequences.List.AddTail("/ultraboard");
	URL.DenySequences.List.AddTail("/empower");
	URL.DenySequences.List.AddTail("/pals-cgi");
	URL.DenySequences.List.AddTail("/htgrep");
	URL.DenySequences.List.AddTail("/.nsconfig");
	URL.DenySequences.List.AddTail("/catinfo");
	URL.DenySequences.List.AddTail("/sweditservlet");
	URL.DenySequences.List.AddTail("/cybercop");
	URL.DenySequences.List.AddTail("/webcart/");
	URL.DenySequences.List.AddTail("/rmp_query");
	URL.DenySequences.List.AddTail("/rpm_query");
	URL.DenySequences.List.AddTail("/servlet/servletexec");
	URL.DenySequences.List.AddTail("/admin-serv/config/admpw");
	URL.DenySequences.List.AddTail("/c32web.exe/changeadminpassword");
	URL.DenySequences.List.AddTail("/graphics/sml3com");
	URL.DenySequences.List.AddTail("/jsp/snp/*.snp");
	URL.DenySequences.List.AddTail("_authchangeurl");
	URL.DenySequences.List.AddTail("/dbadmin");
	URL.DenySequences.List.AddTail("/myadmin");
	URL.DenySequences.List.AddTail("/mysqladmin");
	URL.DenySequences.List.AddTail("/mysql-admin");
	URL.DenySequences.List.AddTail("/phpadmin");
	URL.DenySequences.List.AddTail("/phpmyadmin");
	URL.DenySequences.List.AddTail("/fckeditor");
	URL.DenySequences.List.AddTail("slurpconfirm404");
	URL.DenySequences.List.AddTail("/thisdoesnotexistahaha.");
	URL.DenySequences.List.AddTail("/xmlrpc."); //xmlrpc.php
	URL.DenySequences.List.AddTail("/powershell"); //WinRM Powershell (Exchange 2010)
	//URL.DenySequences.List.AddTail("//"); //also blocks (http://)
	URL.DenySequences.List.AddTail("/./");
	
	URL.DenyRegex.Action = Action::Disabled;
	URL.DenyRegex.Map.RemoveAll();

	//URL: Only allow certain first characters of a URL (must be lowercase)
	URL.Allow.Action = Action::Block;
	URL.Allow.List.RemoveAll();
	URL.Allow.List.AddTail("/");				//allow all relative URLs (http 1.0)
	URL.Allow.List.AddTail("http://");			//absolute URLs (http 1.1 compliant webserver or proxy server)
	URL.Allow.List.AddTail("https://");			//https absolute URL
	//URL.Allow.List.AddTail("ftp://");			//ftp request on http port (allow proxy? network request is not supported? can be exploited? TODO: check this)
	//URL.Allow.List.AddTail("gopher://");		//gopher request on http port (allow proxy?)
	
	URL.ExcludedURL.Enabled = false;
	URL.ExcludedURL.List.RemoveAll();
#ifdef PRIVATEBUILD
	URL.ExcludedURL.Enabled = true;
	URL.ExcludedURL.List.AddTail("/downloads/WebKnight/Robots/Robots.xml");
#endif

	URL.RFCCompliantURL = Action::Block;
	URL.RFCCompliantHTTPURL = Action::Block;
	URL.BadParser = Action::Block;
	URL.UseRawScan = true;					//Use URL raw scanning

	URL.RequestsLimit.Action = Action::Disabled;
	URL.RequestsLimit.MaxCount = 3000;
	URL.RequestsLimit.MaxTime = 2;
	
	//FULLPATH
	Path.ParentPath = Action::Block;
	Path.SpecialWhitespace = Action::Block;
	Path.Escaping = Action::Block;				//if true, you cannot use '%' in a filename
	Path.Characters.Action = Action::Block;
	Path.Characters.Value = "*?\"<>|$^#+=~;";	//a windows filename cannot contain "\/:*?"<>|" and block "$^#+=~" as well
	Path.MultipleColons = Action::Block;

	//PATH
	Path.Dot = Action::Disabled; //deny dot in path

	//PATH: allowed paths (must be lowercase)
	//      NO ending '\' otherwise problems with virtual dirs (if those virtual dirs
	//      are mapped to a physical directory with no ending '\'). For best practices
	//      I suggest you add a trailing '\' for each virtual dir in IIS (this tightens
	//      security). Once you have done that, you can add a trailing '\' in here too.
	//      I wonder if you can exploit this? (TODO)
	Path.AllowPaths.Action = Action::Block;
	Path.AllowPaths.List.RemoveAll();
	Path.AllowPaths.List.AddTail("c:\\inetpub\\www");			//default web site & www.domain.com ...
	Path.AllowPaths.List.AddTail("c:\\inetpub\\scripts");			//Scripts (/scripts)
	Path.AllowPaths.List.AddTail("c:\\winnt\\help\\iishelp");		//IISHelp (/iishelp) W2K
	Path.AllowPaths.List.AddTail("c:\\windows\\help\\iishelp");		//IISHelp (/iishelp) XP
	Path.AllowPaths.List.AddTail("c:\\inetpub\\iissamples");		//IIS samples
	Path.AllowPaths.List.AddTail("c:\\winnt\\web\\printers");		//Printers (/printers)
	Path.AllowPaths.List.AddTail("c:\\winnt\\system32\\inetsrv\\iisadmin");//IIS Administration Website & /iisadmin (individual site administration)
	//Path.AllowPaths.List.AddTail("c:\\winnt\\system32\\inetsrv\\iisadmpwd");//IIS change password interface (/iisadmpwd)
	Path.AllowPaths.List.AddTail("c:\\winnt\\system32\\certsrv");	//Certificate Services
	Path.AllowPaths.List.AddTail("c:\\program files\\common files\\system\\msadc"); //MSADC (/msadc) & 
	Path.AllowPaths.List.AddTail("c:\\program files\\common files\\microsoft shared\\web server extensions"); //Web Server Extensions (FrontPage) (/_vti_bin)
	Path.AllowPaths.List.AddTail("m:\\");							//Outlook Web Access
	Path.AllowPaths.List.AddTail("c:\\program files\\exchsrvr\\exchweb");//Outlook Web Access
	Path.AllowPaths.List.AddTail("\\\\.\\backofficestorage");		//Exchange admin ("/ExAdmin")
	Path.AllowPaths.List.AddTail("c:\\program files");				//allow all applications to add functionality via the web server
	Path.AllowPaths.List.AddTail("c:\\www");						//custom web site
	Path.AllowPaths.List.AddTail("c:\\web");						//custom web site
	Path.AllowPaths.List.AddTail("d:\\www");						//custom web site
	Path.AllowPaths.List.AddTail("d:\\web");						//custom web site
	Path.AllowPaths.List.AddTail("d:\\inetpub\\");					//custom web site
	Path.AllowPaths.List.AddTail("e:\\www");						//custom web site
	Path.AllowPaths.List.AddTail("e:\\web");						//custom web site
	Path.AllowPaths.List.AddTail("e:\\inetpub\\");					//custom web site
	Path.AllowPaths.List.AddTail("f:\\www");						//custom web site
	Path.AllowPaths.List.AddTail("f:\\web");						//custom web site
	Path.AllowPaths.List.AddTail("f:\\inetpub\\");					//custom web site

	//FILENAME
	Filename.UseRawScan = true;
	Filename.Characters.Action = Action::Block;
	Filename.Characters.Value = "\\:/*?\"<>|$^#+=~;"; //a windows filename cannot contain "\/:*?"<>|" and block "$^#+=~" as well
	Filename.DefaultDocument = Action::Disabled;

	Filename.Deny.Action = Action::Block;
	Filename.Deny.List.RemoveAll();
	//FILENAME: Deny almost all Windows 2000 commands (must be lowercase)
	Filename.Deny.List.AddTail("arp.exe");
	Filename.Deny.List.AddTail("at.exe");
	Filename.Deny.List.AddTail("atmadm.exe");
	Filename.Deny.List.AddTail("attrib.exe");
	Filename.Deny.List.AddTail("cacls.exe");
	Filename.Deny.List.AddTail("chkdsk.exe");
	Filename.Deny.List.AddTail("chkntfs.exe");
	Filename.Deny.List.AddTail("cipher.exe");
	Filename.Deny.List.AddTail("cluster.exe");
	Filename.Deny.List.AddTail("cmd.exe");
	Filename.Deny.List.AddTail("comp.exe");
	Filename.Deny.List.AddTail("date.exe");
	Filename.Deny.List.AddTail("debug.exe");
	Filename.Deny.List.AddTail("diskcomp.com");
	Filename.Deny.List.AddTail("diskcopy.com");
	Filename.Deny.List.AddTail("diskperf.exe");
	Filename.Deny.List.AddTail("doskey.exe");
	Filename.Deny.List.AddTail("edlin.exe");
	Filename.Deny.List.AddTail("exe2bin.exe");
	Filename.Deny.List.AddTail("expand.exe");
	Filename.Deny.List.AddTail("fc.exe");
	Filename.Deny.List.AddTail("find.exe");
	Filename.Deny.List.AddTail("findstr.exe");
	Filename.Deny.List.AddTail("forcedos.exe");
	Filename.Deny.List.AddTail("format.exe");
	Filename.Deny.List.AddTail("ftp.exe");
	Filename.Deny.List.AddTail("graphics.com");
	Filename.Deny.List.AddTail("hostname.exe");
	Filename.Deny.List.AddTail("ipconfig.exe");
	Filename.Deny.List.AddTail("ipxroute.exe");
	Filename.Deny.List.AddTail("label.exe");
	Filename.Deny.List.AddTail("loadfix.exe");
	Filename.Deny.List.AddTail("mem.exe");
	Filename.Deny.List.AddTail("mode.com");
	Filename.Deny.List.AddTail("mountvol.exe");
	Filename.Deny.List.AddTail("nbtstat.exe");
	Filename.Deny.List.AddTail("net.exe");
	Filename.Deny.List.AddTail("netsh.exe");
	Filename.Deny.List.AddTail("netstat.exe");
	Filename.Deny.List.AddTail("nslookup.exe");
	Filename.Deny.List.AddTail("pathping.exe");
	Filename.Deny.List.AddTail("ping.exe");
	Filename.Deny.List.AddTail("rcp.exe");
	Filename.Deny.List.AddTail("replace.exe");
	Filename.Deny.List.AddTail("rexec.exe");
	Filename.Deny.List.AddTail("route.exe");
	Filename.Deny.List.AddTail("rsh.exe");
	Filename.Deny.List.AddTail("runas.exe");
	Filename.Deny.List.AddTail("rundll.exe");	//deny running dlls
	Filename.Deny.List.AddTail("rundll32.exe");	//deny running dlls
	Filename.Deny.List.AddTail("runonce.exe");
	Filename.Deny.List.AddTail("setver.exe");
	Filename.Deny.List.AddTail("subst.exe");
	Filename.Deny.List.AddTail("tcmsetup.exe");
	Filename.Deny.List.AddTail("telnet.exe"); //not in win2k help -> command reference!
	Filename.Deny.List.AddTail("tftp.exe"); //is also blocked by scanning for ftp.exe
	Filename.Deny.List.AddTail("time.exe");
	Filename.Deny.List.AddTail("winnt.exe");
	Filename.Deny.List.AddTail("winnt32.exe");
	Filename.Deny.List.AddTail("xcopy.exe");
	//FILENAME: script engines
	Filename.Deny.List.AddTail("cscript.exe");
	Filename.Deny.List.AddTail("wscript.exe");
	//FILENAME: W2008 and later admin tools (IIS has CGI and ISAPI restrictions, so should not work by default)
	Filename.Deny.List.AddTail("bitsadmin.exe");	//Joe McCray https://www.youtube.com/watch?v=qBVThFwdYTc
	Filename.Deny.List.AddTail("powershell.exe");
	Filename.Deny.List.AddTail("wmic.exe");
	Filename.Deny.List.AddTail("web.config");
	//FILENAME: Deny common applications used in hacking/scanning
	Filename.Deny.List.AddTail("command.com");
	Filename.Deny.List.AddTail("cmd1.exe");
	Filename.Deny.List.AddTail("root.exe");
	Filename.Deny.List.AddTail("shell.exe");
	Filename.Deny.List.AddTail("iisreset.exe");
	Filename.Deny.List.AddTail("formmail.");		//.cgi & .pl
	Filename.Deny.List.AddTail("mailform.");		//.cgi & .pl
	Filename.Deny.List.AddTail("nc.exe");		//netcat
	Filename.Deny.List.AddTail("netcat.exe");	//netcat
	Filename.Deny.List.AddTail("sumthin");		//found in some script kiddie stuff
	//Filename.Deny.List.AddTail("default.ida");
	Filename.Deny.List.AddTail("whisker.ida");
	Filename.Deny.List.AddTail("whisker.idc");
	Filename.Deny.List.AddTail("whisker.idq");
	Filename.Deny.List.AddTail("whisker.htw");
	Filename.Deny.List.AddTail("whisker.htr");
	Filename.Deny.List.AddTail("carbo.dll");
	Filename.Deny.List.AddTail("ctguestb.idc");
	Filename.Deny.List.AddTail("details.idc");
	Filename.Deny.List.AddTail("w3proxy.dll");	//ms proxy access
	Filename.Deny.List.AddTail("sam._");
	Filename.Deny.List.AddTail("sensepost.exe");
	Filename.Deny.List.AddTail("achg.htr");
	Filename.Deny.List.AddTail("anot.htr");
	Filename.Deny.List.AddTail("adctest.asp");
	Filename.Deny.List.AddTail("ism.dll");
	Filename.Deny.List.AddTail("bdir.htr");
	Filename.Deny.List.AddTail("codebrws.asp");
	Filename.Deny.List.AddTail("form_jscript.asp");
	Filename.Deny.List.AddTail("form_vbscript.asp");
	Filename.Deny.List.AddTail("servervariables_jscript.asp");
	Filename.Deny.List.AddTail("fpcount.exe");
	Filename.Deny.List.AddTail("_vti_inf.html");	//frontpage extensions
	Filename.Deny.List.AddTail("postinfo.html"); //frontpage extensions
	Filename.Deny.List.AddTail("fp30reg.dll");	//frontpage extensions
	Filename.Deny.List.AddTail("fp4areg.dll");	//frontpage extensions
	Filename.Deny.List.AddTail("shtml.dll");		//frontpage extensions
	Filename.Deny.List.AddTail("shtml.exe");		//frontpage extensions
	Filename.Deny.List.AddTail("fpsrvadm.exe");	//frontpage extensions
	Filename.Deny.List.AddTail("fpremadm.exe");	//frontpage extensions
	Filename.Deny.List.AddTail("fpadmin.htm");	//frontpage extensions
	Filename.Deny.List.AddTail("fpadmcgi.exe");	//frontpage extensions
	Filename.Deny.List.AddTail("cfgwiz.exe");	//frontpage extensions
	Filename.Deny.List.AddTail("authors.pwd");	//frontpage extensions
	Filename.Deny.List.AddTail("author.exe");	//frontpage extensions
	Filename.Deny.List.AddTail("author.dll");	//frontpage extensions
	Filename.Deny.List.AddTail("administrators.pwd");//frontpage extensions
	Filename.Deny.List.AddTail("access.cnf");	//frontpage extensions
	Filename.Deny.List.AddTail("service.cnf");	//frontpage extensions
	Filename.Deny.List.AddTail("service.pwd");	//frontpage extensions
	Filename.Deny.List.AddTail("service.stp");	//frontpage extensions
	Filename.Deny.List.AddTail("services.cnf");	//frontpage extensions
	Filename.Deny.List.AddTail("svcacl.cnf");	//frontpage extensions
	Filename.Deny.List.AddTail("users.pwd");		//frontpage extensions
	Filename.Deny.List.AddTail("writeto.cnf");	//frontpage extensions
	Filename.Deny.List.AddTail("dvwssr.dll");	//frontpage extensions
	Filename.Deny.List.AddTail("getdrvs.exe");
	Filename.Deny.List.AddTail("global.asa");
	Filename.Deny.List.AddTail("$data");
	Filename.Deny.List.AddTail("msadcs.dll");
	Filename.Deny.List.AddTail("newdsn.exe");
	Filename.Deny.List.AddTail("search97.vts");
	Filename.Deny.List.AddTail("viewcode.");
	Filename.Deny.List.AddTail("showcode.");
	Filename.Deny.List.AddTail("site.csc");
	Filename.Deny.List.AddTail("srch.htm");
	Filename.Deny.List.AddTail("uploadn.asp");
	Filename.Deny.List.AddTail("logonfrm.asp");	//owa dos
	Filename.Deny.List.AddTail("cgimail.exe");
	Filename.Deny.List.AddTail("quickstore.cfg");
	Filename.Deny.List.AddTail("bigconf.cgi");
	Filename.Deny.List.AddTail("storemgr.pw");
	Filename.Deny.List.AddTail("admin.pw");
	Filename.Deny.List.AddTail("test.");
	Filename.Deny.List.AddTail("password.php3");
	Filename.Deny.List.AddTail("password.txt");
	Filename.Deny.List.AddTail("passwd.txt");
	Filename.Deny.List.AddTail("passwd.php");
	Filename.Deny.List.AddTail("passwd.php3");
	Filename.Deny.List.AddTail("submit.cgi");
	Filename.Deny.List.AddTail("ss.cfg");
	Filename.Deny.List.AddTail("ncl_items.html");
	Filename.Deny.List.AddTail("stat_what.log");
	Filename.Deny.List.AddTail("easylog.html");
	Filename.Deny.List.AddTail("analyse.cgi");
	Filename.Deny.List.AddTail("admin.cgi");
	Filename.Deny.List.AddTail("admin.php");
	Filename.Deny.List.AddTail("admin.pl");
	Filename.Deny.List.AddTail("access-options.txt");
	Filename.Deny.List.AddTail("access.log");
	Filename.Deny.List.AddTail("access-log");
	Filename.Deny.List.AddTail("awebvisit.stat");
	Filename.Deny.List.AddTail("dan_o.dat");
	Filename.Deny.List.AddTail("hits.txt");
	Filename.Deny.List.AddTail("log.htm");
	Filename.Deny.List.AddTail("log.html");
	Filename.Deny.List.AddTail("logfile");
	Filename.Deny.List.AddTail("logfile.htm");
	Filename.Deny.List.AddTail("logfile.html");
	Filename.Deny.List.AddTail("logfile.txt");
	Filename.Deny.List.AddTail("logger.html");
	Filename.Deny.List.AddTail("stat.htm");
	Filename.Deny.List.AddTail("stats.htm");
	Filename.Deny.List.AddTail("stats.html");
	Filename.Deny.List.AddTail("stats.txt");
	Filename.Deny.List.AddTail("webaccess.htm");
	Filename.Deny.List.AddTail("whois_raw.cgi");
	Filename.Deny.List.AddTail("localstart.asp");	//local start document
	Filename.Deny.List.AddTail(".asa.");				//.asp. bug
	Filename.Deny.List.AddTail(".asp.");				//.asp. bug
	Filename.Deny.List.AddTail(".asax.");				//code behind access
	Filename.Deny.List.AddTail(".aspx.");
	Filename.Deny.List.AddTail("trace.axd");			//ASP.NET tracing
	Filename.Deny.List.AddTail("webplus");
	Filename.Deny.List.AddTail("websendmail");
	Filename.Deny.List.AddTail("dcboard.cgi");
	Filename.Deny.List.AddTail("dcforum.cgi");
	Filename.Deny.List.AddTail("mmstdod.cgi");
	Filename.Deny.List.AddTail("cvsweb.cgi");
	Filename.Deny.List.AddTail("php.cgi");
	Filename.Deny.List.AddTail("maillist.pl");
	Filename.Deny.List.AddTail("perl.exe");
	Filename.Deny.List.AddTail("rguest.exe");
	Filename.Deny.List.AddTail("rwwwshell.pl");
	Filename.Deny.List.AddTail("textcounter.pl");
	Filename.Deny.List.AddTail("uploader.exe");
	Filename.Deny.List.AddTail("webhits.exe");
	Filename.Deny.List.AddTail("webgais");
	Filename.Deny.List.AddTail("finger");
	Filename.Deny.List.AddTail("perlshop.cgi");
	Filename.Deny.List.AddTail("pfdisplay.cgi");
	Filename.Deny.List.AddTail("args.bat");
	Filename.Deny.List.AddTail("at-admin.cgi");
	Filename.Deny.List.AddTail("bnbform.cgi");
	Filename.Deny.List.AddTail("wais.pl");
	Filename.Deny.List.AddTail("wguest.exe");
	Filename.Deny.List.AddTail("classifieds.cgi");
	Filename.Deny.List.AddTail("environ.pl");
	Filename.Deny.List.AddTail("filemail.pl");
	Filename.Deny.List.AddTail("man.sh");
	Filename.Deny.List.AddTail("snork.bat");
	Filename.Deny.List.AddTail("blat.exe");
	Filename.Deny.List.AddTail("day5datacopier.cgi");
	Filename.Deny.List.AddTail("day5datanotifier.cgi");
	Filename.Deny.List.AddTail("hsx.cgi");
	Filename.Deny.List.AddTail("s.cgi");
	Filename.Deny.List.AddTail("yabb.cgi");
	Filename.Deny.List.AddTail("post-query");
	Filename.Deny.List.AddTail("visadmin.exe");
	Filename.Deny.List.AddTail("dumpenv.pl");
	Filename.Deny.List.AddTail("snorkerz.cmd");
	Filename.Deny.List.AddTail("win-c-sample.exe");
	Filename.Deny.List.AddTail("w3tvars.pm");
	Filename.Deny.List.AddTail("lwgate");
	Filename.Deny.List.AddTail("flexform");
	Filename.Deny.List.AddTail("www-admin.pl");
	Filename.Deny.List.AddTail("sendform.cgi");
	Filename.Deny.List.AddTail("ppdscgi.exe");
	Filename.Deny.List.AddTail("upload.pl");
	Filename.Deny.List.AddTail("anyform2");
	Filename.Deny.List.AddTail("machineinfo");
	Filename.Deny.List.AddTail("bb-hist.sh");
	Filename.Deny.List.AddTail("pals-cgi");
	Filename.Deny.List.AddTail("webspirs.cgi");
	Filename.Deny.List.AddTail("tstisapi.dll");
	Filename.Deny.List.AddTail("testisapi.dll");
	Filename.Deny.List.AddTail("sendmessage.cgi");
	Filename.Deny.List.AddTail("lastlines.cgi");
	Filename.Deny.List.AddTail("zml.cgi");
	Filename.Deny.List.AddTail("ads.cgi");
	Filename.Deny.List.AddTail("postinfo.asp");
	Filename.Deny.List.AddTail("repost.asp");
	Filename.Deny.List.AddTail("queryhit.htm");
	Filename.Deny.List.AddTail("counter.exe");
	Filename.Deny.List.AddTail("cached_feed.cgi");
	Filename.Deny.List.AddTail("shopping_cart.mdb");
	Filename.Deny.List.AddTail("password.mdb");
	Filename.Deny.List.AddTail("check.txt");
	Filename.Deny.List.AddTail("checks.txt");
	Filename.Deny.List.AddTail("mylog.phtml");
	Filename.Deny.List.AddTail("mlog.phtml");
	Filename.Deny.List.AddTail("convert.bas");
	Filename.Deny.List.AddTail("cpshost.dll");
	Filename.Deny.List.AddTail("smssend.php");
	Filename.Deny.List.AddTail("txt2html.cgi");
	Filename.Deny.List.AddTail("console.exe");
	Filename.Deny.List.AddTail("sojourn.cgi");
	//Filename.Deny.List.AddTail("ping");	//"ping" generates too much false positives: "shopping"
	Filename.Deny.List.AddTail("ftp.pl");
	Filename.Deny.List.AddTail("poll_it_ssi_v2.0.cgi");
	Filename.Deny.List.AddTail("source.asp");
	Filename.Deny.List.AddTail("guestbook.pl");
	Filename.Deny.List.AddTail("import.txt");
	Filename.Deny.List.AddTail("count.cgi");
	Filename.Deny.List.AddTail("catalog.nsf");
	Filename.Deny.List.AddTail("domcfg.nsf");
	Filename.Deny.List.AddTail("domlog.nsf");
	Filename.Deny.List.AddTail("log.nsf");
	Filename.Deny.List.AddTail("names.nsf");
	Filename.Deny.List.AddTail("windmail.exe");
	Filename.Deny.List.AddTail("quikstore.cfg");
	Filename.Deny.List.AddTail("order.log");
	Filename.Deny.List.AddTail("webdist.cgi");
	Filename.Deny.List.AddTail("ws_ftp.ini");
	Filename.Deny.List.AddTail("jdkrqnotify.exe");
	Filename.Deny.List.AddTail("infosrch.cgi");
	Filename.Deny.List.AddTail("code.php3");
	Filename.Deny.List.AddTail("search.vts");
	Filename.Deny.List.AddTail("ax-admin.cgi");
	Filename.Deny.List.AddTail("axs.cgi");
	Filename.Deny.List.AddTail("cachemgr.cgi");
	Filename.Deny.List.AddTail("dfire.cgi");
	Filename.Deny.List.AddTail("web-map.cgi");
	Filename.Deny.List.AddTail("responder.cgi");
	Filename.Deny.List.AddTail("read.php3");
	Filename.Deny.List.AddTail("violation.php3");
	Filename.Deny.List.AddTail("get32.exe");
	Filename.Deny.List.AddTail("cgitest.exe");
	Filename.Deny.List.AddTail("ftpsavecsp.dll");
	Filename.Deny.List.AddTail("ftpsavecvp.dll");
	Filename.Deny.List.AddTail("ftpsave.dll");
	Filename.Deny.List.AddTail("contextadmin.html");
	Filename.Deny.List.AddTail("architext_query.pl");
	Filename.Deny.List.AddTail("wwwboard.pl");
	Filename.Deny.List.AddTail("db_mysql.inc");
	Filename.Deny.List.AddTail("cs.exe");
	Filename.Deny.List.AddTail("bizdb1-search.cgi");
	Filename.Deny.List.AddTail("bb-hostsvc.sh");
	Filename.Deny.List.AddTail("pscoerrpage.htm");
	Filename.Deny.List.AddTail("gwweb.exe");
	Filename.Deny.List.AddTail("openview5.exe");
	Filename.Deny.List.AddTail("rpcproxy.dll");		//Windows 2003 (RPC over HTTP Proxy)
	Filename.Deny.List.AddTail("read_dump.php");
	Filename.Deny.List.AddTail("backdoor");

	//coldfusion
	Filename.Deny.List.AddTail("cfcache.map");		//coldfusion exploit
	Filename.Deny.List.AddTail("exprcalc.cfm");		//coldfusion exploit
	Filename.Deny.List.AddTail("beaninfo.cfm");		//coldfusion exploit
	Filename.Deny.List.AddTail("application.cfm");	//coldfusion exploit
	Filename.Deny.List.AddTail("getfile.cfm");		//coldfusion exploit
	Filename.Deny.List.AddTail("addcontent.cfm");	//coldfusion exploit
	Filename.Deny.List.AddTail("fileexists.cfm");	//coldfusion exploit
	Filename.Deny.List.AddTail("evaluate.cfm");		//coldfusion exploit
	Filename.Deny.List.AddTail("displayopenedfile.cfm");//coldfusion exploit
	Filename.Deny.List.AddTail("mainframeset.cfm");	//coldfusion exploit
	Filename.Deny.List.AddTail("cfmlsyntaxcheck.cfm");//coldfusion exploit
	Filename.Deny.List.AddTail("onrequestend.cfm");	//coldfusion exploit
	Filename.Deny.List.AddTail("startstop.html");	//coldfusion exploit
	Filename.Deny.List.AddTail("gettempdirectory.cfm");//coldfusion exploit
	//file copies
	Filename.Deny.List.AddTail("copy of "); //on W2003
	Filename.Deny.List.AddTail(" - copy.");  //on W7+
	//FILENAME: Deny DOS devices
	Filename.Deny.List.AddTail("nul");
	Filename.Deny.List.AddTail("lpt1");
	Filename.Deny.List.AddTail("lpt2");
	Filename.Deny.List.AddTail("lpt3");
	Filename.Deny.List.AddTail("lpt4");
	Filename.Deny.List.AddTail("aux");
	Filename.Deny.List.AddTail("prn");
	Filename.Deny.List.AddTail("com1");
	Filename.Deny.List.AddTail("com2");
	Filename.Deny.List.AddTail("com3");
	Filename.Deny.List.AddTail("com4");
	//FILENAME: Deny certain *nix commands
	CSignatures::UnixCommands(Filename.Deny.List);

	Filename.Monitor.Enabled = false;
	Filename.Monitor.List.RemoveAll(); //lowercase!
#ifdef PRIVATEBUILD
	Filename.Monitor.Enabled = true;
	Filename.Monitor.List.AddTail("webknight.zip");
	//Filename.Monitor.List.AddTail("robots.xml");
	//Filename.Monitor.List.AddTail("bot.asp");
#else
	Filename.Monitor.List.AddTail("robots.txt");
#endif

	//EXTENSION: Allowed extensions (Common MIME types) (lowercase!)
	Extensions.Allow.Action = Action::Disabled;
	Extensions.Allow.List.RemoveAll();
	Extensions.Allow.List.AddTail("");			//always allow default document & no extension!!!
	Extensions.Allow.List.AddTail(".htm");		//text/html
	Extensions.Allow.List.AddTail(".html");		//text/html
	Extensions.Allow.List.AddTail(".mdl");		//text/html
	Extensions.Allow.List.AddTail(".htt");		//text/webviewhtml
	Extensions.Allow.List.AddTail(".htc");		//text/x-component
	Extensions.Allow.List.AddTail(".xml");		//text/xml
	Extensions.Allow.List.AddTail(".wml");		//wml
	Extensions.Allow.List.AddTail(".dtd");		//text/html
	Extensions.Allow.List.AddTail(".css");		//text/css (style sheet)
	Extensions.Allow.List.AddTail(".uls");		//text/iuls (netmeeting link)
	Extensions.Allow.List.AddTail(".wsc");		//text/scriptlet
	Extensions.Allow.List.AddTail(".vcf");		//text/x-vcard
	Extensions.Allow.List.AddTail(".sgm");		//sgml
	Extensions.Allow.List.AddTail(".sgml");		//sgml
	Extensions.Allow.List.AddTail(".vrml");		//vrml
	Extensions.Allow.List.AddTail(".wrl");		//vrml
	Extensions.Allow.List.AddTail(".cur");
	Extensions.Allow.List.AddTail(".ani");
	Extensions.Allow.List.AddTail(".js");		//javascript download
	Extensions.Allow.List.AddTail(".class");		//java applet
	Extensions.Allow.List.AddTail(".sfw");		//shockwave flash
	Extensions.Allow.List.AddTail(".cfm");		//ColdFusion
	Extensions.Allow.List.AddTail(".cfml");		//ColdFusion
	Extensions.Allow.List.AddTail(".txt");		//text/plain
	Extensions.Allow.List.AddTail(".asc");		//ascii file
	Extensions.Allow.List.AddTail(".doc");		//doc
	Extensions.Allow.List.AddTail(".ai");		//postscript
	Extensions.Allow.List.AddTail(".eps");		//postscript
	Extensions.Allow.List.AddTail(".ps");		//postscript
	Extensions.Allow.List.AddTail(".vsd");		//visio
	Extensions.Allow.List.AddTail(".mpp");		//ms project
	Extensions.Allow.List.AddTail(".pdf");		//pdf
	Extensions.Allow.List.AddTail(".wk4");		
	Extensions.Allow.List.AddTail(".rtf");		//rich text format
	Extensions.Allow.List.AddTail(".wmf");		//windows media file
	Extensions.Allow.List.AddTail(".mcw");
	Extensions.Allow.List.AddTail(".wps");
	Extensions.Allow.List.AddTail(".wpg");
	Extensions.Allow.List.AddTail(".xls");		//excel
	Extensions.Allow.List.AddTail(".csv");		//comma separated
	Extensions.Allow.List.AddTail(".xlw");		//excel
	Extensions.Allow.List.AddTail(".ppt");		//powerpoint
	Extensions.Allow.List.AddTail(".pot");		//powerpoint template
	Extensions.Allow.List.AddTail(".png");		//image
	Extensions.Allow.List.AddTail(".jpe");		//image
	Extensions.Allow.List.AddTail(".jpg");		//image
	Extensions.Allow.List.AddTail(".jpeg");		//image
	Extensions.Allow.List.AddTail(".gif");		//image
	Extensions.Allow.List.AddTail(".tif");		//image
	Extensions.Allow.List.AddTail(".tiff");		//image
	Extensions.Allow.List.AddTail(".bmp");		//image
	Extensions.Allow.List.AddTail(".xbm");		//image
	Extensions.Allow.List.AddTail(".ico");		//image
	Extensions.Allow.List.AddTail(".pcx");		//image
	Extensions.Allow.List.AddTail(".ief");		//image
	Extensions.Allow.List.AddTail(".rgb");		//image
	Extensions.Allow.List.AddTail(".ppm");		//image
	Extensions.Allow.List.AddTail(".pbm");		//image
	Extensions.Allow.List.AddTail(".pnm");		//image
	Extensions.Allow.List.AddTail(".mpg");		//video
	Extensions.Allow.List.AddTail(".mpeg");		//video
	Extensions.Allow.List.AddTail(".mpe");		//video
	Extensions.Allow.List.AddTail(".mp2");		//video
	Extensions.Allow.List.AddTail(".avi");		//video
	Extensions.Allow.List.AddTail(".mov");		//video
	Extensions.Allow.List.AddTail(".qt");		//video
	Extensions.Allow.List.AddTail(".asf");		//video
	Extensions.Allow.List.AddTail(".ivf");		//video
	Extensions.Allow.List.AddTail(".lsx");		//video
	Extensions.Allow.List.AddTail(".wm");		//video/x-ms-wm
	Extensions.Allow.List.AddTail(".wmv");		//video/x-ms-wmv
	Extensions.Allow.List.AddTail(".wmx");		//video/x-ms-wmx
	Extensions.Allow.List.AddTail(".wvx");		//video/x-ms-wvx
	Extensions.Allow.List.AddTail(".asd");		//asf description
	Extensions.Allow.List.AddTail(".asx");		//video
	Extensions.Allow.List.AddTail(".divx");		//video
	Extensions.Allow.List.AddTail(".wma");		//audio/x-ms-wma
	Extensions.Allow.List.AddTail(".mp3");		//audio
	Extensions.Allow.List.AddTail(".m3u");		//audio
	Extensions.Allow.List.AddTail(".aif");		//audio
	Extensions.Allow.List.AddTail(".aiff");		//audio
	Extensions.Allow.List.AddTail(".aifc");		//audio
	Extensions.Allow.List.AddTail(".au");		//audio
	Extensions.Allow.List.AddTail(".snd");		//audio
	Extensions.Allow.List.AddTail(".ra");		//realaudio
	Extensions.Allow.List.AddTail(".ram");		//realaudio
	Extensions.Allow.List.AddTail(".wav");		//audio
	Extensions.Allow.List.AddTail(".mod");		//audio
	Extensions.Allow.List.AddTail(".mid");		//audio
	Extensions.Allow.List.AddTail(".midi");		//audio
	Extensions.Allow.List.AddTail(".cdf");		//channel definition format (w3c)
	Extensions.Allow.List.AddTail(".pac");		//proxy auto configuration
	Extensions.Allow.List.AddTail(".zip");		//compress
	Extensions.Allow.List.AddTail(".rar");		//compress
	Extensions.Allow.List.AddTail(".tar");		//compress
	Extensions.Allow.List.AddTail(".gtar");		//compress
	Extensions.Allow.List.AddTail(".arj");		//compress
	Extensions.Allow.List.AddTail(".jar");		//compress
	Extensions.Allow.List.AddTail(".gz");		//compress
	Extensions.Allow.List.AddTail(".z");			//compress
	Extensions.Allow.List.AddTail(".tgz");		//compress
	Extensions.Allow.List.AddTail(".cab");		//potentially dangerous?
	Extensions.Allow.List.AddTail(".exe");		//download
	Extensions.Allow.List.AddTail(".hqx");		//mac binhex
	Extensions.Allow.List.AddTail(".msi");/*
	Extensions.Allow.List.AddTail(".idq");
	Extensions.Allow.List.AddTail(".htw");
	Extensions.Allow.List.AddTail(".ida");
	Extensions.Allow.List.AddTail(".idc");
	Extensions.Allow.List.AddTail(".shtm");
	Extensions.Allow.List.AddTail(".shtml");
	Extensions.Allow.List.AddTail(".stm");
	Extensions.Allow.List.AddTail(".htr");*/
	Extensions.Allow.List.AddTail(".jsp");	//java server pages
	Extensions.Allow.List.AddTail(".asp");	//asp
	//Extensions.Allow.List.AddTail(".asa");	//asp global.asa
	Extensions.Allow.List.AddTail(".aspx");	//asp.NET
	Extensions.Allow.List.AddTail(".ashx");	//asp.net web handler
	Extensions.Allow.List.AddTail(".asmx");	//web service
	Extensions.Allow.List.AddTail(".cer");	//certificates
	Extensions.Allow.List.AddTail(".p7b");	//Certificate Services
	Extensions.Allow.List.AddTail(".crl");	//certificate revocation list
	//Extensions.Allow.List.AddTail(".cdx");
	//Extensions.Allow.List.AddTail(".printer");

	//EXTENSION: Denied extensions (lowercase!)
	Extensions.Deny.Action = Action::Block;
	Extensions.Deny.List.RemoveAll();/*
	//EXTENSION: Deny ASP requests
	Extensions.Deny.List.AddTail(".asp");
	Extensions.Deny.List.AddTail(".aspx");
	Extensions.Deny.List.AddTail(".ashx");
	Extensions.Deny.List.AddTail(".cer");
	Extensions.Deny.List.AddTail(".cdx");
	Extensions.Deny.List.AddTail(".crl");*/
	Extensions.Deny.List.AddTail(".asa");//asp global file, should not be downloaded
	//Deny ASP.NET critical files
	Extensions.Deny.List.AddTail(".ascx");		//forbidden by asp.net
	//Extensions.Deny.List.AddTail(".axd");		//WebResources (too much used: Sharepoint Server 2007...)
	Extensions.Deny.List.AddTail(".config");		//forbidden by asp.net (config)
	//Extensions.Deny.List.AddTail(".cs");		//forbidden by asp.net (c#) (also blocks ".css" style sheet!)
	Extensions.Deny.List.AddTail(".csproj");		//forbidden by asp.net (c# project)
	Extensions.Deny.List.AddTail(".licx");		//forbidden by asp.net (licenses)
	Extensions.Deny.List.AddTail(".rem");		//remoting ASP.NET
	Extensions.Deny.List.AddTail(".resources");	//forbidden by asp.net (resources)
	Extensions.Deny.List.AddTail(".resx");		//forbidden by asp.net (resources - xml)
	Extensions.Deny.List.AddTail(".soap");		//remoting & handling soap requests
	Extensions.Deny.List.AddTail(".vb");			//forbidden by asp.net (vb code)
	Extensions.Deny.List.AddTail(".vbproj");		//forbidden by asp.net (vb project)
	Extensions.Deny.List.AddTail(".vsdisco");	//dynamic discovery: security issue!!!! http://msdn.microsoft.com/msdnmag/issues/02/08/XMLFiles/default.aspx
	Extensions.Deny.List.AddTail(".webinfo");	//forbidden by asp.net
	//EXTENSION: Deny executables that could run on the server
	//Extensions.Deny.List.AddTail(".exe");		//this file should be allowed (download)
	//Extensions.Deny.List.AddTail(".dll");		//deny isapi extension
	//Extensions.Deny.List.AddTail(".ocx");		//(TODO: check this)
	//Extensions.Deny.List.AddTail(".drv");
	//Extensions.Deny.List.AddTail(".sys");
	//Extensions.Deny.List.AddTail(".vxd");
	Extensions.Deny.List.AddTail(".scr");
	Extensions.Deny.List.AddTail(".vbs");		//Visual Basic Script
	Extensions.Deny.List.AddTail(".vbe");		//Visual Basic Script (Encrypted)
	Extensions.Deny.List.AddTail(".bat");
	Extensions.Deny.List.AddTail(".btr");		//Frontpage dependency files
	Extensions.Deny.List.AddTail(".cmd");
	//Extensions.Deny.List.AddTail(".cgi");
	Extensions.Deny.List.AddTail(".com");
	Extensions.Deny.List.AddTail(".cpl");
	Extensions.Deny.List.AddTail(".pif");		//??? can be run??? need to check this out */
	//EXTENSION: Deny infrequently used scripts
	Extensions.Deny.List.AddTail(".htw");		//Maps to webhits.dll - Index Server
	Extensions.Deny.List.AddTail(".ida");		//Maps to idq.dll - Index Server
	Extensions.Deny.List.AddTail(".idq");		//Maps to idq.dll - Index Server
	Extensions.Deny.List.AddTail(".htr");		//Maps to ism.dll - Legacy administrative tool
	Extensions.Deny.List.AddTail(".idc");		//Maps to httpodbc.dll - Legacy database access tool
	Extensions.Deny.List.AddTail(".shtm");		//Maps to ssinc.dll - Server Side Includes
	Extensions.Deny.List.AddTail(".shtml");		//Maps to ssinc.dll - Server Side Includes
	Extensions.Deny.List.AddTail(".stm");		//Maps to ssinc.dll - Server Side Includes
	Extensions.Deny.List.AddTail(".printer");	//Maps to msw3prt.dll - Internet Printing Services
	//EXTENSION: Deny various static files
	Extensions.Deny.List.AddTail(".bin");		//IIS MetaBase
	Extensions.Deny.List.AddTail(".dmp");		//dumps & sql server logs
	Extensions.Deny.List.AddTail(".dns");		//dns files
	Extensions.Deny.List.AddTail(".evt");		//Event viewer log files
	Extensions.Deny.List.AddTail(".ini");
	Extensions.Deny.List.AddTail(".mdb");
	Extensions.Deny.List.AddTail(".mde");
	Extensions.Deny.List.AddTail(".ldb");		//access locking file
	Extensions.Deny.List.AddTail(".sav");		//backup registry files
	Extensions.Deny.List.AddTail(".adp");
	Extensions.Deny.List.AddTail(".db");		//db & dbf & dbx
	Extensions.Deny.List.AddTail(".cfg");
	Extensions.Deny.List.AddTail(".cnf");
	Extensions.Deny.List.AddTail(".conf");
	//Extensions.Deny.List.AddTail(".config");	//already denied for ASP.NET
	Extensions.Deny.List.AddTail(".ids");		//snort log
	Extensions.Deny.List.AddTail(".rules");		//snort rules
	Extensions.Deny.List.AddTail(".log");
	Extensions.Deny.List.AddTail(".pol");
	Extensions.Deny.List.AddTail(".dom");		//policy template
	Extensions.Deny.List.AddTail(".sec");
	Extensions.Deny.List.AddTail(".bak");
	Extensions.Deny.List.AddTail(".backup");
	Extensions.Deny.List.AddTail(".old");
	Extensions.Deny.List.AddTail(".000");
	Extensions.Deny.List.AddTail(".asp~");
	Extensions.Deny.List.AddTail(".tmp");
	Extensions.Deny.List.AddTail(".acl");
	Extensions.Deny.List.AddTail(".sch");
	Extensions.Deny.List.AddTail(".dat");
	Extensions.Deny.List.AddTail(".mmc");
	Extensions.Deny.List.AddTail(".msc");
	Extensions.Deny.List.AddTail(".sql");
	Extensions.Deny.List.AddTail(".tql");
	Extensions.Deny.List.AddTail(".cns");		//terminal client settings
	Extensions.Deny.List.AddTail(".inc");		//ASP include file
	Extensions.Deny.List.AddTail(".sam");		//password file
	Extensions.Deny.List.AddTail(".htgroup");	//found in snort rules (*nix only)
	Extensions.Deny.List.AddTail(".htpasswd");
	Extensions.Deny.List.AddTail(".htaccess");
	Extensions.Deny.List.AddTail(".wwwacl");
	Extensions.Deny.List.AddTail(".www_acl");
    Extensions.Deny.List.AddTail(".ewl");
	//EXTENSION: cmdlets
	Extensions.Deny.List.AddTail(".ws");     //Windows Script
    //Extensions.Deny.List.AddTail(".wsf");    //Windows Script
	//Extensions.Deny.List.AddTail(".wsc");    //Windows Script
	//Extensions.Deny.List.AddTail(".wsh");    //Windows Script
	Extensions.Deny.List.AddTail(".ps1");    //PowerShell
	//Extensions.Deny.List.AddTail(".ps1xml"); //PowerShell
	Extensions.Deny.List.AddTail(".ps2");    //PowerShell
	//Extensions.Deny.List.AddTail(".ps2xml"); //PowerShell
	Extensions.Deny.List.AddTail(".psc1");   //PowerShell
	Extensions.Deny.List.AddTail(".psc2");   //PowerShell
	Extensions.Deny.List.AddTail(".msh");    //Monad Script File (PowerShell)
	//Extensions.Deny.List.AddTail(".msh1");   //Monad Script File (PowerShell)
	//Extensions.Deny.List.AddTail(".msh2");   //Monad Script File (PowerShell)
	//Extensions.Deny.List.AddTail(".mshxml"); //Monad Script File (PowerShell)
	//Extensions.Deny.List.AddTail(".msh1xml");//Monad Script File (PowerShell)
	//Extensions.Deny.List.AddTail(".msh2xml");//Monad Script File (PowerShell)

	//EXTENSION: ripping protection
	Extensions.RequestsLimit.Action = Action::Disabled;
	Extensions.RequestsLimit.MaxCount = 200;
	Extensions.RequestsLimit.MaxTime = 4;
	Extensions.LimitExtensions.RemoveAll();
	Extensions.LimitExtensions.AddTail(".jpg");
	Extensions.LimitExtensions.AddTail(".png");
	Extensions.LimitExtensions.AddTail(".bmp");
	Extensions.LimitExtensions.AddTail(".exe");
	Extensions.LimitExtensions.AddTail(".zip");

	//HEADERS
	Headers.MaxLength.Action = Action::Disabled;
	Headers.MaxLength.Value = 8192;
	Headers.DenyHeaders.Action = Action::Block;
	Headers.DenyHeaders.List.RemoveAll();
	Headers.DenyHeaders.List.AddTail("Translate:");			//needed by MS-WebDAV & Outlook Web Access
	Headers.DenyHeaders.List.AddTail("If:");				//WebDAV
	Headers.DenyHeaders.List.AddTail("Lock-Token:");		//WebDAV
	Headers.DenyHeaders.List.AddTail("Timeout:");			//WebDAV
	Headers.DenyHeaders.List.AddTail("Transfer-Encoding:"); //disables message encoding (chunked encoding,...) (TODO: needed by ASP?)
	Headers.DenyHeaders.List.AddTail("Content-Encoding:");	//disables entity encoding
	Headers.DenyHeaders.List.AddTail("Content-Transfer-Encoding:");	//not allowed in HTTP (rfc 2616)
	Headers.DenyHeaders.List.AddTail("Proxy-Authenticate:");
	Headers.DenyHeaders.List.AddTail("WWW-Authenticate:");
	Headers.DenyHeaders.List.AddTail("Ms-Echo-Request:");	//found this in asp.dll, don't know what it means, but looks very disturbing, so block it! (TODO: check this) (also found in winhttp.dll,wininet.dll,msxml3.dll)
	Headers.DenyHeaders.List.AddTail("Ms-Echo-Reply:");		//found in asp.dll: HTTP_MS_ECHO_REPLY ??? (TODO)
	Headers.DenyHeaders.List.AddTail("SOAPAction:");					//SOAP
	Headers.DenyHeaders.List.AddTail("BITS-Packet-Type:");				//BITS upload REQUEST/RESPONSE
	//Headers.DenyHeaders.List.AddTail("BITS-Protocol:");					//BITS upload		  RESPONSE
	Headers.DenyHeaders.List.AddTail("BITS-Session-Id:");				//BITS upload REQUEST/RESPONSE
	Headers.DenyHeaders.List.AddTail("BITS-Supported-Protocols:");		//BITS upload REQUEST
	//Headers.DenyHeaders.List.AddTail("BITS-Host-Id:");					//BITS upload		  RESPONSE
	//Headers.DenyHeaders.List.AddTail("BITS-Host-Id-Fallback-Timeout:");	//BITS upload		  RESPONSE
	//Headers.DenyHeaders.List.AddTail("BITS-Received-Content-Range:");	//BITS upload		  RESPONSE
	//Headers.DenyHeaders.List.AddTail("BITS-Reply-URL:");				//BITS upload		  RESPONSE
	//Headers.DenyHeaders.List.AddTail("BITS-Error-Code:");				//BITS upload		  RESPONSE
	//Headers.DenyHeaders.List.AddTail("BITS-Error-Context:");			//BITS upload		  RESPONSE

	Headers.DenyHeaders.List.AddTail("BITS-Original-Request-URL:");		//BITS Notification REQUEST
	Headers.DenyHeaders.List.AddTail("BITS-Request-DataFile-Name:");	//BITS Notification REQUEST
	Headers.DenyHeaders.List.AddTail("BITS-Response-DataFile-Name:");	//BITS Notification REQUEST
	//Headers.DenyHeaders.List.AddTail("BITS-Static-Response-URL:");		//BITS Notification			RESPONSE
	//Headers.DenyHeaders.List.AddTail("BITS-Copy-File-To-Destination:");	//BITS Notification			RESPONSE
	Headers.DenyHeaders.List.AddTail("Content-Name:");		//BITS REQUEST

	Headers.DenyHeaders.List.AddTail("Sec-WebSocket-Key:"); 		//WebSocket	REQUEST
	Headers.DenyHeaders.List.AddTail("Sec-WebSocket-Extensions:");	//WebSocket	REQUEST/RESPONSE
	//Headers.DenyHeaders.List.AddTail("Sec-WebSocket-Accept:");		//WebSocket			RESPONSE
	Headers.DenyHeaders.List.AddTail("Sec-WebSocket-Protocol:");	//WebSocket	REQUEST/RESPONSE
	Headers.DenyHeaders.List.AddTail("Sec-WebSocket-Version:");		//WebSocket	REQUEST/RESPONSE

	//HOST
	Host.RFCCompliant = Action::Block;
	Host.Excluded.Enabled = false;
	Host.Excluded.List.RemoveAll();
	Host.AllowHosts.Action = Action::Disabled;
	Host.AllowHosts.List.RemoveAll();
	Host.DenyHosts.Action = Action::Block;
	Host.DenyHosts.List.RemoveAll();
	Host.DenyHosts.List.AddTail("localhost");
	Host.DenyHosts.List.AddTail("127.0.0.1"); //should also block 127.0.0.0/8 -> let's block all IP addresses in host headers
	Host.DenyHosts.List.AddTail("[::1]");
	Host.AllowDenyHostsAccess.Enabled = true;
	Host.AllowDenyHostsAccess.List.RemoveAll();
	Host.AllowDenyHostsAccess.List.AddTail("127.0.0.1");
	Host.AllowDenyHostsAccess.List.AddTail("::1");

	//COOKIE
#ifdef PRIVATEBUILD
	Cookie.HttpOnly = true;
	Cookie.Secure = true;
#else
	Cookie.HttpOnly = false;
	Cookie.Secure = false;
#endif
	Cookie.SQLInjection = Action::Block;
	Cookie.EncodingExploits = Action::Disabled; //blocks Google Analytics cookies
	Cookie.DirectoryTraversal = Action::Disabled;
	Cookie.HighBitShellcode = Action::Disabled;
	Cookie.SpecialWhitespace = Action::Block;
	Cookie.Parameters.Pollution = Action::Block;
	Cookie.Parameters.NameRequireRegex.Action = Action::Block;
	Cookie.Parameters.NameRequireRegex.Value = "^[a-zA-Z0-9_\\.\\-$]+$"; //also allow $ sign for $Version and $Path
	Cookie.Parameters.InputValidation = Action::Block;
	Cookie.MaxVariableLength.Action = Action::Block;
	Cookie.MaxVariableLength.Value = 1024;
	Cookie.DenySequences.Action = Action::Block;
	Cookie.DenySequences.List.RemoveAll();
	CSignatures::RemoteFileInclusion(Cookie.DenySequences.List);

	//USER AGENTS
	UserAgent.Empty = Action::Block;
#ifdef PRIVATEBUILD
	UserAgent.RequireCharacter.Action = Action::Block;
#else
	UserAgent.RequireCharacter.Action = Action::Disabled;
#endif
	UserAgent.RequireCharacter.Value = "/-._";
	UserAgent.NonRFC = Action::Block;
	UserAgent.SQLInjection = Action::Block;
	UserAgent.HighBitShellcode = Action::Disabled;	//Korean contains high bit...
	UserAgent.SpecialWhitespace = Action::Block;
#ifdef PRIVATEBUILD
	UserAgent.CurrentDate.Action = Action::Monitor; //Allow for useragents database
#else
	UserAgent.CurrentDate.Action = Action::Block;
#endif
	UserAgent.CurrentDate.List.RemoveAll();
	UserAgent.CurrentDate.List.AddTail("%Y-%m-%d");
	UserAgent.CurrentDate.List.AddTail("%Y%m%d");  //also blocks TCO_ and nate_app
	UserAgent.CurrentDate.List.AddTail("%m/%d/%Y");
	UserAgent.CurrentDate.List.AddTail("%d/%m/%Y");
	UserAgent.CurrentDate.List.AddTail("%Y/%m/%d");
	UserAgent.Switching.Action = Action::Block;
#ifdef PRIVATEBUILD
	UserAgent.Switching.MaxCount = 15;
#else
	UserAgent.Switching.MaxCount = 30;
#endif
	UserAgent.Switching.MaxTime = 5;
	UserAgent.DenyUserAgents.Action = Action::Disabled;
	UserAgent.DenyUserAgents.List.RemoveAll();

	UserAgent.DenySequences.Action = Action::Disabled;
	UserAgent.DenySequences.List.RemoveAll();	//lowercase!

	UserAgent.Excluded.Enabled = false;
	UserAgent.Excluded.List.RemoveAll();

	ContentType.Allow.Action = Action::Block;
	ContentType.Allow.List.RemoveAll();
	ContentType.Allow.List.AddTail("application/x-www-form-urlencoded");	//simple post
	//ContentType.Allow.List.AddTail("multipart/form-data");				//posts like fileuploads
	//ContentType.Allow.List.AddTail("text/xml");							//allow SOAP/XMLRPC posts
	//ContentType.Allow.List.AddTail("application/json");					//allow JSON
	ContentType.Deny.Action = Action::Block;
	ContentType.Deny.List.RemoveAll();
	ContentType.Deny.List.AddTail("application/x-www-form-urlencoded;"); //parameters not allowed for this content type
	ContentType.Deny.List.AddTail("text/html charset=");
	ContentType.Deny.List.AddTail("text/html,");
	ContentType.Deny.List.AddTail("text/html; charset=utf8");
	ContentType.Deny.List.AddTail("text/html; encoding='utf-8'");
	ContentType.Deny.List.AddTail("multipart/form-data; boundary=---------------------------4314239228695");
	ContentType.Deny.List.AddTail("multipart/form-data; boundary=---------------------------41184676334"); //BOT for JCE (they copied it from Firefox as FF also uses this boundary in the first attempt at uploading. Second upload = different boundary)
	ContentType.Deny.List.AddTail("multipart/form-data; boundary=----------------------------7a22987a9ede"); //Joomla exploit
	ContentType.Deny.List.AddTail("multipart/form-data; boundary=---------------------------7e116d19044c");//Auto Spider
	ContentType.Deny.List.AddTail("multipart/form-data; boundary=---------------------------7d529a1d23092a");
	ContentType.Deny.List.AddTail("multipart/form-data; boundary=---------------------------7dd9a6509ce");//upload exploit
	ContentType.Deny.List.AddTail("multipart/form-data; boundary=------------------------924145cd91f1df83");
	ContentType.Deny.List.AddTail("multipart/form-data; boundary=xYzZY");
	ContentType.Deny.List.AddTail("multipart/form-data; boundary=(UploadBoundary)");
	ContentType.Deny.List.AddTail("multipart/form-data; boundary=----WebKitFormBoundaryScAb2VeaY3T4kgPd");
	ContentType.Deny.List.AddTail("multipart/form-data; Charset=UTF-8; boundary=T0PHackTeam_WEBFuck");
	ContentType.MaxLength.Action = Action::Block;
	ContentType.MaxLength.Map.RemoveAll();
	//TODO: 4.7 - ApplyConstraints lowercase?
	ContentType.MaxLength.Map.SetAt("application/x-www-form-urlencoded","49152"); //ASP classic only reads first 100000 bytes, 48K is prefetched by IIS
	ContentType.MaxLength.Map.SetAt("application/x-www-utf8-encoded","49152");	//Exchange OWA
	ContentType.MaxLength.Map.SetAt("application/json","65536");
	ContentType.MaxLength.Map.SetAt("application/soap+xml","65536");
	ContentType.MaxLength.Map.SetAt("application/wrml","65536");
	ContentType.MaxLength.Map.SetAt("application/yaml","65536");
	ContentType.MaxLength.Map.SetAt("application/x-yaml","65536");
	ContentType.MaxLength.Map.SetAt("application/xml","65536");
	ContentType.MaxLength.Map.SetAt("multipart/","3145728"); //3MB
	ContentType.MaxLength.Map.SetAt("multipart/form-data","3145728"); //3MB
	ContentType.MaxLength.Map.SetAt("multipart/mixed","3145728"); //3MB
	ContentType.MaxLength.Map.SetAt("text/html","65536");
	ContentType.MaxLength.Map.SetAt("text/plain","4096");
	ContentType.MaxLength.Map.SetAt("text/xml","65536");
	ContentType.MaxContentLength.Action = Action::Block;
	ContentType.MaxContentLength.Value = "5300642";//(see bugtraq: Content-Length DoS 5300643)//"30000000";//max value of content length header (to prevent overflow, it cannot be longer than 9 characters)

	TransferEncoding.Allow.Action = Action::Block;
	TransferEncoding.Allow.List.RemoveAll();
	TransferEncoding.Allow.List.AddTail("chunked");
	TransferEncoding.Allow.List.AddTail("identity");
	TransferEncoding.Allow.List.AddTail("gzip");
	TransferEncoding.Allow.List.AddTail("compress");
	TransferEncoding.Allow.List.AddTail("deflate");
	TransferEncoding.Deny.Action = Action::Disabled;
	TransferEncoding.Deny.List.RemoveAll();

	Headers.SQLInjection = Action::Disabled;
	Headers.EncodingExploits = Action::Disabled;				//needed for 'Referer:' (like with Google cache)
	Headers.DirectoryTraversal = Action::Block;
	Headers.HighBitShellcode = Action::Disabled;				//deny high bit characters (only allow US-ASCII)
	Headers.DenySequences.Action = Action::Block;
	Headers.DenySequences.List.RemoveAll();					//list should be lowercase
	Headers.DenySequences.List.AddTail("cmd.exe");
	Headers.DenySequences.List.AddTail("root.exe");
	Headers.DenySequences.List.AddTail("system32");
	Headers.DenySequences.List.AddTail("cscript.exe");
	Headers.DenySequences.List.AddTail("wscript.exe");
	Headers.DenySequences.List.AddTail("bitsadmin.exe");	//Joe McCray https://www.youtube.com/watch?v=qBVThFwdYTc
	Headers.DenySequences.List.AddTail("powershell.exe");
	Headers.DenySequences.List.AddTail("wmic.exe");
	Headers.DenySequences.List.AddTail("web.config");
	Headers.DenySequences.List.AddTail("xp_cmdshell");
	Headers.DenySequences.List.AddTail("cirestriction=none");
	Headers.DenySequences.List.AddTail("cihilitetype=full");
	Headers.DenySequences.List.AddTail("ciwebhitsfile");
	CSignatures::MaliciousHTML(Headers.DenySequences.List);
	CSignatures::JavaScript(Headers.DenySequences.List);
	CSignatures::VBScript(Headers.DenySequences.List);
	CSignatures::ColdFusionExploits(Headers.DenySequences.List);
	CSignatures::PHPExploits(Headers.DenySequences.List);
	//Headers.DenySequences.List.AddTail("user-agent: webtrends security analyzer");	//Webtrends Security Analyzer user agent string
	Headers.DenySequences.List.AddTail("cookie: =");					//Cookie ASP exploit

	Headers.DenyRegex.Action = Action::Disabled;
	Headers.DenyRegex.Map.RemoveAll();

	//Referrer
	Referrer.UseScan = true;
	Referrer.RFCCompliantURL = Action::Block;
	Referrer.RFCCompliantHTTPURL = Action::Block;
	Referrer.BadParser = Action::Block;
	Referrer.EncodingExploits = Action::Disabled;
	Referrer.Characters.Action = Action::Disabled;
	Referrer.Characters.Value = "";
	Referrer.HighBitShellcode = Action::Disabled;
	Referrer.SpecialWhitespace = Action::Block;
	Referrer.SQLInjection = Action::Block;
	Referrer.Allow.Action = Action::Block;
	Referrer.Allow.List.RemoveAll();
	//Referrer.Allow.List.AddTail("");			//empty referer is always allowed
	//Referrer.Allow.List.AddTail("/");			//RFC: Referer = absolute-URI / partial-URI but we deny partial-URI (relative URI)
	Referrer.Allow.List.AddTail("http://");
	Referrer.Allow.List.AddTail("https://");
	Referrer.Allow.List.AddTail("about:blank");	//RFC 7231 (same as no referrer)
	Referrer.Allow.List.AddTail("android-app://");
	Referrer.Deny.Action = Action::Block;
	Referrer.Deny.List.RemoveAll();
	Referrer.Deny.List.AddTail("google.com");
	Referrer.Deny.List.AddTail("http://www.googlebot.com/bot.html");
	Referrer.Deny.List.AddTail("http://www.google.com/?q=foobar");
	Referrer.Deny.List.AddTail("http://www.google.com/q?=foobar");
	Referrer.Deny.List.AddTail("http://www.whitehouse.gov/");
	Referrer.Deny.List.AddTail("http://www.google.com"); //non-https shows query details
	Referrer.Deny.List.AddTail("http://www.baidu.com"); //non-https shows query details
	Referrer.DenySequences.Action = Action::Block;
	Referrer.DenySequences.List.RemoveAll();
	Referrer.Excluded.Enabled = true;
	Referrer.Excluded.List.RemoveAll();
	Referrer.Excluded.List.AddTail("http://search.yahoo.com/search");
	Referrer.Excluded.List.AddTail("https://search.yahoo.com/search");
	Referrer.Excluded.List.AddTail("http://images.search.yahoo.com/");
	Referrer.Excluded.List.AddTail("https://images.search.yahoo.com/");
	Referrer.Excluded.List.AddTail("http://googleads.g.doubleclick.net/");
	Referrer.Excluded.List.AddTail("https://googleads.g.doubleclick.net/");

	Referrer.HotLinking = false;
	Referrer.HotLinkingUrls.RemoveAll();
	Referrer.HotLinkingUrls.AddTail("/add");
	Referrer.HotLinkingUrls.AddTail("/admin");
	Referrer.HotLinkingUrls.AddTail("/del");
	Referrer.HotLinkingUrls.AddTail("/edit");
	Referrer.HotLinkingUrls.AddTail("/login");
	Referrer.HotLinkingUrls.AddTail("/profile");
	Referrer.HotLinkingUrls.AddTail("/register");
	Referrer.HotLinkingUrls.AddTail("/send");
	Referrer.HotLinkingUrls.AddTail("/update");
	Referrer.HotLinkingFileExtensions.RemoveAll();
	Referrer.HotLinkingFileExtensions.AddTail(".bmp");
	Referrer.HotLinkingFileExtensions.AddTail(".jpg");
	Referrer.HotLinkingFileExtensions.AddTail(".gif");
	Referrer.HotLinkingFileExtensions.AddTail(".png");
	Referrer.HotLinkingFileExtensions.AddTail(".exe");
	Referrer.HotLinkingFileExtensions.AddTail(".zip");
	Referrer.HotLinkingAllowDomains.Action = Action::Block;
	Referrer.HotLinkingAllowDomains.List.RemoveAll();
	Referrer.HotLinkingAllowDomains.List.AddTail("localhost");
	Referrer.HotLinkingAllowDomains.List.AddTail("127.0.0.1");
	Referrer.HotLinkingAllowDomains.List.AddTail("::1"); //0:0:0:0:0:0:0:1
	Referrer.HotLinkingDenyDomains.Action = Action::Disabled;
	Referrer.HotLinkingDenyDomains.List.RemoveAll();
	Referrer.HotLinkingUseHostHeader = true;
	Referrer.HotLinkingBlankReferrer = Action::Disabled;
#ifdef PRIVATEBUILD
	Referrer.HotLinking = true;
	Referrer.HotLinkingAllowDomains.List.AddTail("www.paypal.com");
	//Referrer.HotLinkingBlankReferrer = Action::Block;
#endif

	//VERBS: Allowed verbs list (case sensitive: see RFC 2616!)
	Verbs.AllowVerbs.Action = Action::Block;
	Verbs.AllowVerbs.List.RemoveAll();
	//Verbs.AllowVerbs.List.AddTail("OPTIONS");	//rfc & biztalk & frontpage & sharepoint
	Verbs.AllowVerbs.List.AddTail("GET");			//rfc - simple request (must allow!)
	Verbs.AllowVerbs.List.AddTail("HEAD");		//rfc - simple request (must allow!)
	Verbs.AllowVerbs.List.AddTail("POST");		//rfc - post data
	//Verbs.AllowVerbs.List.AddTail("PUT");		//rfc & biztalk & commerce
	//Verbs.AllowVerbs.List.AddTail("DELETE");	//rfc & biztalk
	//Verbs.AllowVerbs.List.AddTail("TRACE");		//rfc
	//Verbs.AllowVerbs.List.AddTail("CONNECT");	//rfc
	//Verbs.AllowVerbs.List.AddTail("PROPFIND");	//biztalk & webdav
	//Verbs.AllowVerbs.List.AddTail("PROPPATCH");	//OWA & webdav
	//Verbs.AllowVerbs.List.AddTail("MKCOL");		//biztalk & webdav
	//Verbs.AllowVerbs.List.AddTail("POLL");		//exchange 2000
	//Verbs.AllowVerbs.List.AddTail("DEBUG");		//ASP.NET debugging
	//Verbs.AllowVerbs.List.AddTail("BITS_POST");	//BITS

	//VERBS: Denied verbs list (must be uppercase! lowercase & variants will also be blocked)
	Verbs.DenyVerbs.Action = Action::Disabled;
	Verbs.DenyVerbs.List.RemoveAll();
	Verbs.DenyVerbs.List.AddTail("PROPFIND");  //these verbs will block WebDAV (warning: WebDAV
	Verbs.DenyVerbs.List.AddTail("PROPPATCH"); //is required for Outlook Web Access and "web folders")
	Verbs.DenyVerbs.List.AddTail("MKCOL");
	Verbs.DenyVerbs.List.AddTail("DELETE");
	Verbs.DenyVerbs.List.AddTail("PUT");
	Verbs.DenyVerbs.List.AddTail("COPY");
	Verbs.DenyVerbs.List.AddTail("MOVE");
	Verbs.DenyVerbs.List.AddTail("LOCK");
	Verbs.DenyVerbs.List.AddTail("UNLOCK");
	Verbs.DenyVerbs.List.AddTail("OPTIONS");
	Verbs.DenyVerbs.List.AddTail("POLL");
	Verbs.DenyVerbs.List.AddTail("SEARCH");	//used by MS & rfc proposal (didn't make it)
	Verbs.DenyVerbs.List.AddTail("CONNECT");	//I added this one, the ones above are from urlscan
	Verbs.DenyVerbs.List.AddTail("TRACE");	//I added this one too (rfc)
	//found these in winhttp.dll (TODO: what are these & exploit? IIS says "not implemented")
	Verbs.DenyVerbs.List.AddTail("M-POST");		//winhttp.dll SOAP, xmlrpc,...
	Verbs.DenyVerbs.List.AddTail("PIN");			//winhttp.dll TODO: what is it & exploit?
	Verbs.DenyVerbs.List.AddTail("INVOKE");		//winhttp.dll used by sharepoint portal server TODO: what is it & exploit?
	Verbs.DenyVerbs.List.AddTail("CHECKOUT");		//winhttp.dll & rfc proposal (didn't make it) TODO: what is it & exploit?
	Verbs.DenyVerbs.List.AddTail("CHECKIN");		//winhttp.dll & rfc proposal (didn't make it) TODO: what is it & exploit?
	Verbs.DenyVerbs.List.AddTail("NOTIFY");		//winhttp.dll
	Verbs.DenyVerbs.List.AddTail("UNSUBSCRIBE");	//winhttp.dll
	Verbs.DenyVerbs.List.AddTail("SUBSCRIBE");	//winhttp.dll
	Verbs.DenyVerbs.List.AddTail("BDELETE");		//winhttp.dll
	Verbs.DenyVerbs.List.AddTail("BPROPPATCH");	//winhttp.dll
	Verbs.DenyVerbs.List.AddTail("BPROPFIND");	//winhttp.dll
	Verbs.DenyVerbs.List.AddTail("BCOPY");		//winhttp.dll
	Verbs.DenyVerbs.List.AddTail("BMOVE");		//winhttp.dll
	Verbs.DenyVerbs.List.AddTail("UNLINK");		//winhttp.dll
	Verbs.DenyVerbs.List.AddTail("LINK");			//winhttp.dll
	Verbs.DenyVerbs.List.AddTail("TRACK");		//found in MSDN library: returns the original request (like TRACE)
	Verbs.DenyVerbs.List.AddTail("SHOWMETHOD");	//http method proposal that didn't make it into the RFC
	Verbs.DenyVerbs.List.AddTail("TEXTSEARCH");	//http method proposal that didn't make it into the RFC
	Verbs.DenyVerbs.List.AddTail("SPACEJUMP");	//http method proposal that didn't make it into the RFC
	Verbs.DenyVerbs.List.AddTail("SUBSCRIPTIONS");//urlscan (urlscan_exchange2000.ini)
	Verbs.DenyVerbs.List.AddTail("ACL");			//urlscan (urlscan_exchange2000.ini)
	Verbs.DenyVerbs.List.AddTail("NOTIFY");		//urlscan (urlscan_exchange2000.ini)
	Verbs.DenyVerbs.List.AddTail("DEBUG");		//ASP.NET debugging
	Verbs.DenyVerbs.List.AddTail("X-MS-ENUMATTS");//Found in Exchange 2000 SDK http://msdn.microsoft.com/library/default.asp?url=/library/en-us/wss/wss/_webdav_x-ms-enumatts.asp
	Verbs.DenyVerbs.List.AddTail("RPC_IN_DATA");	//RPC-over-HTTP (new in Windows2003)
	Verbs.DenyVerbs.List.AddTail("RPC_OUT_DATA");	//RPC-over-HTTP (new in Windows2003)
	Verbs.DenyVerbs.List.AddTail("BITS_POST");		//BITS
	Verbs.DenyVerbs.List.AddTail("M-SEARCH");		//UPnP http://serverfault.com/questions/64884/network-flooded-with-m-search-packets-what-does-it-mean

	Verbs.DenyPayload.Action = Action::Block;
	Verbs.DenyPayload.List.AddTail("GET");
	Verbs.DenyPayload.List.AddTail("HEAD");
	//Verbs.DenyPayload.List.AddTail("OPTIONS");	//can have payload in the future (as per RFC 7231)
	Verbs.DenyPayload.List.AddTail("TRACE");	//denied as per RFC 7231
	Verbs.DenyPayload.List.AddTail("DELETE");

	CSignatures::SQLInjection(SQLi.Keywords);
	SQLi.AllowedCount = 1;
	SQLi.NormalizeWhitespace = true;
	SQLi.ReplaceNumericWithOne = true;

	CSignatures::EncodingExploits(EncodingExploits.Keywords);
#ifdef PRIVATEBUILD
	EncodingExploits.Keywords.AddTail("'");
#endif
	EncodingExploits.ScanDoubleEncoding = true;
	EncodingExploits.ScanInvalidUTF8 = true;
	EncodingExploits.Regex.RemoveAll();
	CSignatures::EncodingExploits(EncodingExploits.Regex);

	//QUERYSTRING
	QueryString.SQLInjection = Action::Block;			//Deny SQL injection in querystring
	QueryString.EncodingExploits = Action::Block;		//Deny embedded encoding exploits
	QueryString.DirectoryTraversal = Action::Block;
	QueryString.HighBitShellcode = Action::Disabled;		//deny high bit characters (only allow US-ASCII)
	QueryString.SpecialWhitespace = Action::Block;
	QueryString.MaxLength.Action = Action::Block;
	QueryString.MaxLength.Value = 1024;//4096;	//max length of querystring
	QueryString.Parameters.Pollution = Action::Block;
	QueryString.Parameters.NameRequireRegex.Action = Action::Block;
	QueryString.Parameters.NameRequireRegex.Value = "^[a-zA-Z0-9_\\.\\-]+$";
	QueryString.Parameters.InputValidation = Action::Block;
	QueryString.MaxVariableLength.Action = Action::Block;
	QueryString.MaxVariableLength.Value = 2048;
	QueryString.UseRawScan = true;
	QueryString.DenySequences.Action = Action::Block;			//Deny certain sequences
	QueryString.DenySequences.List.RemoveAll();			//list has to be lowercase
	CSignatures::MaliciousHTML(QueryString.DenySequences.List);
	CSignatures::JavaScript(QueryString.DenySequences.List);
	CSignatures::VBScript(QueryString.DenySequences.List);
	QueryString.DenySequences.List.AddTail("administrators /add");
	QueryString.DenySequences.List.AddTail("cirestriction=none");
	QueryString.DenySequences.List.AddTail("cihilitetype=full");
	QueryString.DenySequences.List.AddTail("ciwebhitsfile");
	QueryString.DenySequences.List.AddTail("cmd.exe");
	QueryString.DenySequences.List.AddTail("root.exe");
	QueryString.DenySequences.List.AddTail("system32");
	QueryString.DenySequences.List.AddTail("cscript.exe");
	QueryString.DenySequences.List.AddTail("wscript.exe");
	QueryString.DenySequences.List.AddTail("bitsadmin.exe");	//Joe McCray https://www.youtube.com/watch?v=qBVThFwdYTc
	QueryString.DenySequences.List.AddTail("powershell.exe");
	QueryString.DenySequences.List.AddTail("wmic.exe");
	QueryString.DenySequences.List.AddTail("web.config");
	QueryString.DenySequences.List.AddTail("xp_cmdshell");
	CSignatures::ColdFusionExploits(QueryString.DenySequences.List);
	CSignatures::PHPExploits(QueryString.DenySequences.List);
	//Netscape Enterprise Server directory view exploit (only via querystring)
	QueryString.DenySequences.List.AddTail("wp-verify-link");
	QueryString.DenySequences.List.AddTail("wp-cs-dump");
	QueryString.DenySequences.List.AddTail("wp-ver-info");
	QueryString.DenySequences.List.AddTail("wp-ver-diff");
	QueryString.DenySequences.List.AddTail("wp-start-ver");
	QueryString.DenySequences.List.AddTail("wp-stop-ver");
	QueryString.DenySequences.List.AddTail("wp-uncheckout");
	QueryString.DenySequences.List.AddTail("wp-html-rend");
	QueryString.DenySequences.List.AddTail("wp-usr-prop");
	//LoadDefaultsUnixCommands(QueryString.DenySequences.List);	//too much collateral damage
	CSignatures::RemoteFileInclusion(QueryString.DenySequences.List);
	//file access
	QueryString.DenySequences.List.AddTail("c:\\");
#ifdef PRIVATEBUILD
	QueryString.DenySequences.List.AddTail("&name=holmes ");
#endif

	QueryString.DenyRegex.Action = Action::Disabled;
	QueryString.DenyRegex.Map.RemoveAll();
	QueryString.ExcludedQueryString.Enabled = false;
	QueryString.ExcludedQueryString.List.RemoveAll();

	//raw data (headers sequences & POST data)
	Global.IsInstalledAsGlobalFilter = true;		//Raw data can only be scanned if filter is a global filter
#ifdef TESTBUILD
	Global.IsInstalledAsGlobalFilter = false;
#endif
	Global.IsInstalledInWebProxy = false;
	Global.SlowHeaderAttack = Action::Block;
	Global.SlowPostAttack = Action::Block;

	Post.RFCCompliant = Action::Block;
	Post.SQLInjection = Action::Block;			//no SQL injection in POST data
	Post.EncodingExploits = Action::Block;		//embedded encoding needed by OWA
	Post.DirectoryTraversal = Action::Block;
	Post.HighBitShellcode = Action::Disabled;		//deny high bit characters (only allow US-ASCII)
	Post.Parameters.Pollution = Action::Block;
	Post.Parameters.NameRequireRegex.Action = Action::Block;
	Post.Parameters.NameRequireRegex.Value = "^[a-zA-Z0-9_\\.\\-$]+$"; //also allow $ sign for webforms
	Post.Parameters.InputValidation = Action::Block;
	Post.MaxVariableLength.Action = Action::Block;
	Post.MaxVariableLength.Value = 2048;
#ifdef PRIVATEBUILD
	Post.DenySequences.Action = Action::Disabled;
#else
	Post.DenySequences.Action = Action::Block;
#endif
	Post.DenySequences.List.RemoveAll();		//list has to be lowercase
	CSignatures::MaliciousHTML(Post.DenySequences.List);
	CSignatures::JavaScript(Post.DenySequences.List);
	CSignatures::VBScript(Post.DenySequences.List);
	Post.DenySequences.List.AddTail("cmd.exe");
	Post.DenySequences.List.AddTail("root.exe");
	Post.DenySequences.List.AddTail("system32");
	Post.DenySequences.List.AddTail("cscript.exe");
	Post.DenySequences.List.AddTail("wscript.exe");
	Post.DenySequences.List.AddTail("bitsadmin.exe");	//Joe McCray https://www.youtube.com/watch?v=qBVThFwdYTc
	Post.DenySequences.List.AddTail("powershell.exe");
	Post.DenySequences.List.AddTail("wmic.exe");
	Post.DenySequences.List.AddTail("web.config");
	Post.DenySequences.List.AddTail("xp_cmdshell");
	Post.DenySequences.List.AddTail("content-encoding:");	//disables entity encoding (bodyparts)
	Post.DenySequences.List.AddTail("content-transfer-encoding:"); //not allowed in HTTP (rfc 2616)
	CSignatures::ColdFusionExploits(Post.DenySequences.List);
	CSignatures::PHPExploits(Post.DenySequences.List);
	CSignatures::RemoteFileInclusion(Post.DenySequences.List);

	Post.DenyRegex.Action = Action::Disabled;
	Post.DenyRegex.Map.RemoveAll();

#ifdef PRIVATEBUILD
	Post.LogLength = 4096;
#else
	Post.LogLength = 1024;
#endif

	//Response Monitor
	ResponseMonitor.RemoveServerHeader = false; //needs to be false for SyncServerHeader
	ResponseMonitor.ChangeServerHeader = false; //needs to be false for SyncServerHeader
	ResponseMonitor.Headers.Enabled = true;
	ResponseMonitor.Headers.Map.RemoveAll();
	ResponseMonitor.Headers.Map.SetAt("Server:","WWW Server/1.1");//"Apache/0.8.4"; //in the form of <application>/<version_major>.<version_minor>
	ResponseMonitor.Headers.Map.SetAt("X-AspNet-Version:","");
	ResponseMonitor.Headers.Map.SetAt("X-AspNetMvc-Version:","");
	ResponseMonitor.Headers.Map.SetAt("X-Powered-By:","");
	ResponseMonitor.Headers.Map.SetAt("X-Content-Type-Options:","nosniff"); //to prevent text/plain as html/css in IE
	ResponseMonitor.Headers.Map.SetAt("X-Frame-Options:","SAMEORIGIN");		//to prevent clickjacking
	ResponseMonitor.Headers.Map.SetAt("X-XSS-Protection:","1; mode=block"); //to prevent xss (should be by default enabled, unless user disabled it in browser)
	ResponseMonitor.LogClientErrors = true;			//http 404 errors, etc.
	ResponseMonitor.LogServerErrors = true;			//http 500 errors...
	ResponseMonitor.ClientErrors.Action = Action::Block;
	ResponseMonitor.ClientErrors.MaxCount = 100;
	ResponseMonitor.ClientErrors.MaxTime = 10;
	ResponseMonitor.ServerErrors.Action = Action::Block;
	ResponseMonitor.ServerErrors.MaxCount = 10;
	ResponseMonitor.ServerErrors.MaxTime = 10;

#ifdef PRIVATEBUILD
	ResponseMonitor.InformationDisclosure.Action = Action::Disabled; //WebKnight.xml download
#else
	ResponseMonitor.InformationDisclosure.Action = Action::Block;
#endif
	ResponseMonitor.InformationDisclosure.Map.RemoveAll();
	CSignatures::PaymentCards(ResponseMonitor.InformationDisclosure.Map);
	CSignatures::ErrorPages(ResponseMonitor.InformationDisclosure.Map);
	
	//Allow compatible web applications
	WebApp.Clear();
#ifdef PRIVATEBUILD
	WebApp.Allow_SOAP = true;
#endif

	//BOTS
	Robots.AllowRobotsFile = true;
	Robots.Dynamic = false;
	Robots.DynamicFile = "robots.asp";
	Robots.DenyAll = false;
	Robots.DenyBad = true;
#ifdef PRIVATEBUILD
	Robots.DenyAggressive.Enabled = true;
#else
	Robots.DenyAggressive.Enabled = false;
#endif
	Robots.DenyAggressive.MaxTime = 3;		//minutes
	Robots.DenyAggressive.MaxCount = 180;	//number of requests
	Robots.BadBotTraps.RemoveAll();
	Robots.BadBotTraps.AddTail("/badbottrap");//badbot trap (case sensitive) and no ending slash (for cyveillance bot!)
	Robots.BadBotTraps.AddTail("/guestbookspamtrap");//for those bots going to "guestbook" urls
	Robots.BadBotTraps.AddTail("/robotsxx.txt");
	Robots.BotTimeout = 36;	//24 (hours)

	Agents.BlockDataMiningCommercial = false;
	Agents.BlockDataMiningPublic = false;
	Agents.BlockDownloadManagers = false;
	Agents.BlockEmailHarvesting = true;
	Agents.BlockGuestbookSpammers = true;
	Agents.BlockHackTools = true;
	Agents.BlockImageDownloaders = false;
	Agents.BlockIndexing = false;
	Agents.BlockMonitoring = false;
	Agents.BlockOfflineBrowsers = false;
	Agents.BlockOtherBad = true;
	Agents.BlockTrademark = false;
	Agents.BlockValidationTools = false;
	Agents.BlockLinkChecking = false;
	Agents.BlockBrowsers = false;
	Agents.BlockMediaPlayers = false;
	Agents.BlockProxies = false;
	Agents.BlockAdware = false;
	Agents.BlockBrowserExtensions = false;
	Agents.BlockSpyware = false;
	Agents.BlockEditing = false;
	//Agents.BlockDevice = false;
	Agents.BlockNewsFeed = false;
	Agents.BlockSearchEngines = false;
	Agents.BlockFilteringSoftware = false;
	Agents.BlockSoftwareComponent = false;
	Agents.BlockTranslation = false;
	Agents.BlockSEO = false;
	Agents.BlockMailClients = false;

#ifdef PRIVATEBUILD
	//Agents.BlockDataMiningCommercial = true; //Allow Google AdSense
	Agents.BlockImageDownloaders = true;
	Agents.BlockMonitoring = true;
	Agents.BlockOfflineBrowsers = true;
	Agents.BlockTrademark = true;
	Agents.BlockValidationTools = true;
	Agents.BlockSEO = true;
#endif
}

inline void CWebKnightSettings::LoadISACompatibility()
{
	//TODO: WebKnight ISA/TMG Server installation
	/*
	 * LoadISACompatibility (no longer necessary with IsInstalledInWebProxy)
	 * WebKnight settings/separate download
	 */

	//Scanning engine
	Engine.AllowLateScanning = true;			//high or low priority (true=low)

	Global.IsInstalledInWebProxy = true;

	//Scanning engine: excluded web instances. These are the web sites you
	//don't want to be scanned by this filter, because they are not normal
	//websites and use their own filter/extension to process requests.
	//Examples are Outlook Web Access, MS Proxy 2.0 (not ISA Server), SQL XML (only blocked if URL queries are enabled(SQL injection))
	Engine.ExcludedInstances.Enabled = false;
	Engine.ExcludedInstances.List.RemoveAll();

	//Authentication
	Authentication.ScanExcludedInstances = false;

	//URL: Deny certain sequences (must be lowercase)
	//RemoveFrom(URL.DenySequences.List,"/scripts");	//scripts (needed by MS Proxy 2.0, frontpage - not by ISA Server)

	/* ISA Server / Forefront TMG
	Event: OnPreprocHeaders
	Client IP: 192.168.10.206
	Username: 
	Host header: proxy:8080
	Additional info about request (event specific): GET
	/array.dll
	Get.Routing.Script
	HTTP/1.1

	BLOCKED: Empty User Agent not allowed
	*/
	/* ISA Server / Forefront TMG
	Event: OnPreprocHeaders
	Client IP: 192.168.10.206
	Username: 
	Host header: update.microsoft.com:443
	Additional info about request (event specific): CONNECT
	BLOCKED: HTTP VERB not allowed
	update.microsoft.com:443
	BLOCKED: URL not in allowed list
	BLOCKED: ':' not allowed in filename
	BLOCKED: accessing/running '.com' file
	HTTP/1.1

	BLOCKED: Empty User Agent not allowed
	*/
	URL.Allow.Action = Action::Disabled;

	/* ISA Server / Forefront TMG
	Event: OnUrlMap
	Client IP: 192.168.10.206
	Username: 
	Host header: tech
	Additional info about request (event specific): w3proxy.dll
	w3proxy.dll
	BLOCKED: Not in allowed path list 'w3proxy.dll'
	BLOCKED: accessing/running 'w3proxy.dll' file
	*/
	/* ISA Server / Forefront TMG
	Event: OnUrlMap
	Client IP: 192.168.10.206
	Username: 
	Host header: tech
	Additional info about request (event specific): 

	BLOCKED: Not in allowed path list ''
	*/
	//OnUrlMap is disabled by IsInstalledInWebProxy so these two lines are now redundant
	Path.AllowPaths.Action = Action::Disabled;
	RemoveFrom(Filename.Deny.List,"w3proxy.dll");	//ms proxy access (also used by ISA server in OnUrlMap)
}

void CWebKnightSettings::Upgrade()
{
	CWebKnightUpgrade::Upgrade(*this);
}

void CWebKnightSettings::Notify(LPCTSTR Message)
{
	Patches.SetAt("<AQTRONIX_WebKnight_Configuration App='Title'/>","<AQTRONIX_WebKnight_Configuration App='Title' Wizard='" + CXML::Encode(Message) + "'/>");
}

void CWebKnightSettings::AddAllList(LPCTSTR item)
{
	AddNotInList(Headers.DenySequences.List,item);
	AddNotInList(QueryString.DenySequences.List,item);
	AddNotInList(Post.DenySequences.List,item);
}

void CWebKnightSettings::AddAllPayloads(LPCTSTR item)
{
	AddNotInList(Cookie.DenySequences.List,item);
	AddNotInList(QueryString.DenySequences.List,item);
	AddNotInList(Post.DenySequences.List,item);
}

void CWebKnightSettings::AddAllRegex(LPCTSTR item, LPCTSTR value, bool AddHeaders)
{
	if(AddHeaders)
		AddNotInMap(Headers.DenyRegex.Map,item,value);
	AddNotInMap(QueryString.DenyRegex.Map,item,value);
	AddNotInMap(Post.DenyRegex.Map,item,value);
}

void CWebKnightSettings::ReplaceAllRegex(LPCTSTR item, LPCTSTR find, LPCTSTR replacement)
{
	ReplaceKeyword(Headers.DenyRegex.Map,item,find,replacement);
	ReplaceKeyword(QueryString.DenyRegex.Map,item,find,replacement);
	ReplaceKeyword(Post.DenyRegex.Map,item,find,replacement);
}

void CWebKnightSettings::ReplaceAllRegex(LPCTSTR find, LPCTSTR replacement)
{
	ReplaceKeyword(Headers.DenyRegex.Map,find,replacement);
	ReplaceKeyword(QueryString.DenyRegex.Map,find,replacement);
	ReplaceKeyword(Post.DenyRegex.Map,find,replacement);
}

bool CWebKnightSettings::WriteToFileXML(LPCTSTR fn)
{
	CString xml("");

	//xml += "<!DOCTYPE WebKnight[\r\n";			//start dtd
	//xml += "<!ELEMENT WebKnightSettings ANY >\r\n";
	//xml += " ]>\r\n";							//end dtd

	xml += "<WebKnightSettings Version='" + CString(APP_VERSION_STRING) + "'>\r\n";	//start entity
	xml += "<WebKnight_Configuration App='Document' NavigationBar='1'/>\r\n";
	xml += "<AQTRONIX_WebKnight_Configuration App='Title'/>\r\n";
	xml += ToXML();
	xml += "</WebKnightSettings>\r\n";		//end entity

	return XML.WriteEntityToFile(fn,xml);
}

bool CWebKnightSettings::WriteToFileINI(LPCTSTR fn)
{
	/* 
	 * Write all settings to a simple INI file
	 * All checks on the file should have been
	 * done before this function is called
	 */

	if(!CHTTPFirewallSettings::WriteToFileINI(fn))
		return false;

	try{

	//BOTS
	WRITE_INI_BOOL(Robots,AllowRobotsFile)
	WRITE_INI_BOOL(Robots,Dynamic)
	WRITE_INI_STRING(Robots,DynamicFile)
	WRITE_INI_BOOL(Robots,DenyAll)
	WRITE_INI_BOOL(Robots,DenyBad)
	WRITE_INI_CACHE(Robots,DenyAggressive)
	WRITE_INI_INT(Robots,BotTimeout)
	WRITE_INI_CSTRINGLIST(Robots,BadBotTraps)

	//BOTS DATABASE
#define CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(name) \
		WritePrivateProfileString("Robots","BlockBots" #name,Agents.Block##name?"1":"0",fn);
	
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(DataMiningCommercial)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(DataMiningPublic)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(DownloadManagers)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(EmailHarvesting)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(GuestbookSpammers)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(HackTools)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(ImageDownloaders)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(Indexing)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(Monitoring)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(OfflineBrowsers)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(OtherBad)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(Trademark)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(ValidationTools)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(LinkChecking)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(Browsers)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(MediaPlayers)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(Proxies)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(Adware)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(BrowserExtensions)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(Spyware)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(Editing)
	//CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(Device)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(NewsFeed)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(SearchEngines)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(FilteringSoftware)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(SoftwareComponent)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(Translation)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(SEO)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_BOTS(MailClients)

	//Web applications
#define CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(name) \
		WritePrivateProfileString("Web Applications","Allow" #name,WebApp.Allow_##name?"1":"0",fn);

	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(FileUploads)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(Unicode)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(OutlookWebAccess)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(OutlookMobileAccess)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(ActiveSync)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(RPCoverHTTP)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(FrontpageExtensions)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(Coldfusion)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(WebDAV)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(IISADMPWD)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(SharePointPortalServer)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(SharePointTeamServices)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(SharePointOffice2007)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(TeamFoundationServer)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(VirtualServer2005)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(CertificateServices)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(BizTalkServer)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(CommerceServer)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(SmallBusinessServer)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(ASP)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(ASPNET)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(ASPNETMVC)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(PHP)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(BITS)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(SOAP)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(JSON)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(REST)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(WinRM)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(WebSocket)
	CWEBKNIGHTSETTINGS_WRITETOFILEINI_WEBAPP(PaypalIPN)

		return true;
	}catch(...){
		return false;
	}
}


bool CWebKnightSettings::ReadFromFileINI(LPCTSTR fn)
{
	if(!CHTTPFirewallSettings::ReadFromFileINI(fn))
		return false;

	try{

		const int sz = SETTINGS_MAX_INI_BUF_SIZE;
		char buf[sz];
		DWORD l(0);

#define WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(name)\
	Agents.Block##name = GetPrivateProfileInt("Robots","BlockBots"#name,Agents.Block##name,fn)>0;

		//BOTS
		READ_INI_BOOL(Robots,AllowRobotsFile)
		READ_INI_BOOL(Robots,Dynamic)
		READ_INI_STRING(Robots,DynamicFile)
		READ_INI_BOOL(Robots,DenyAll)
		READ_INI_BOOL(Robots,DenyBad)
		READ_INI_CACHE(Robots,DenyAggressive)
		READ_INI_INT(Robots,BotTimeout)
		READ_INI_CSTRINGLIST(Robots,BadBotTraps,INI.Cleanup)

		//BOTS DATABASE
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(DataMiningCommercial)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(DataMiningPublic)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(DownloadManagers)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(EmailHarvesting)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(GuestbookSpammers)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(HackTools)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(ImageDownloaders)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(Indexing)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(Monitoring)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(OfflineBrowsers)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(OtherBad)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(Trademark)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(ValidationTools)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(LinkChecking)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(Browsers)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(MediaPlayers)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(Proxies)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(Adware)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(BrowserExtensions)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(Spyware)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(Editing)
		//WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(Device)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(NewsFeed)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(SearchEngines)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(FilteringSoftware)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(SoftwareComponent)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(Translation)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(SEO)
		WEBKNIGHTSETTINGS_READFROMFILEINI_BOTS(MailClients)

		//WEB APPLICATIONS
#define WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(name)\
		WebApp.Allow_##name = GetPrivateProfileInt("Web Applications","Allow"#name,WebApp.Allow_##name,fn)>0;\
		if(WebApp.Allow_##name) CWebApplications::Enable##name(*this);

		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(FileUploads)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(Unicode)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(OutlookWebAccess)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(OutlookMobileAccess)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(ActiveSync)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(RPCoverHTTP)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(FrontpageExtensions)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(Coldfusion)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(WebDAV)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(IISADMPWD)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(SharePointPortalServer)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(SharePointTeamServices)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(SharePointOffice2007)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(TeamFoundationServer)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(VirtualServer2005)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(CertificateServices)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(BizTalkServer)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(CommerceServer)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(SmallBusinessServer)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(ASP)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(ASPNET)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(ASPNETMVC)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(PHP)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(BITS)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(SOAP)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(JSON)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(REST)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(WinRM)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(WebSocket)
		WEBKNIGHTSETTINGS_READFROMFILEINI_WEBAPPS(PaypalIPN)
		
		return true;
	}catch(...){
		LoadDefaults();
		return false;
	}
}

bool CWebKnightSettings::ParseXML(CString& key, CString& val)
{
	//if not a valid key
	if (key=="")
		return false;

#define CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(var,key)\
	else if(name.CompareNoCase("Block_Bots_" #key)==0){	Agents.Block##var = val=="1"?true:false; }

#define CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(var,key)\
	else if(name.CompareNoCase("Allow_" #key)==0){	WebApp.Allow_##var = val=="1"?true:false; if(WebApp.Allow_##var && !IsUpgradeInProgress) CWebApplications::Enable##var(*this); }

	if(!CHTTPFirewallSettings::ParseXML(key,val)){

		CString name = CXML::Decode(CXML::TagName(key));

		//BOTS
		PARSE_XML_BOOL(Robots,AllowRobotsFile,"Allow_Bots_Robots_File")
		else PARSE_XML_BOOL(Robots,Dynamic,"Dynamic_Robots")
		else PARSE_XML_STRING(Robots,DynamicFile,"Dynamic_Robots_File")
		else PARSE_XML_BOOL(Robots,DenyAll,"Deny_Bots_All")
		else PARSE_XML_BOOL(Robots,DenyBad,"Deny_Bots_Bad")
		else PARSE_XML_CSTRINGLIST(Robots,BadBotTraps,"Deny_Bots_BotTraps")
		else PARSE_XML_CACHE(Robots,DenyAggressive,"Deny_Bots_Aggressive")
		else PARSE_XML_INT(Robots,BotTimeout,"Deny_Bots_Timeout",(unsigned int))

		//BOTS DATABASE
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(DataMiningCommercial,Data_Mining_Commercial)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(DataMiningPublic,Data_Mining_Public)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(DownloadManagers,Download_Managers)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(EmailHarvesting,Email_Harvesting)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(GuestbookSpammers,Guestbook_Spammers)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(HackTools,Hack_Tools)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(ImageDownloaders,Image_Downloaders)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(Indexing,Indexing)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(Monitoring,Monitoring)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(OfflineBrowsers,Offline_Browsers)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(OtherBad,Other_Bad)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(Trademark,Trademark)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(ValidationTools,Validation_Tools)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(LinkChecking,Link_Checking)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(Browsers,Browsers)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(MediaPlayers,Media_Players)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(Proxies,Proxies)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(Adware,Adware)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(BrowserExtensions,Browser_Extensions)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(Spyware,Spyware)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(Editing,Editing)
		//CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(Device,Device)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(NewsFeed,News_Feed)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(SearchEngines,Search_Engines)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(FilteringSoftware,Filtering_Software)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(SoftwareComponent,Software_Component)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(Translation,Translation)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(SEO,SEO)
		CWEBKNIGHTSSETTINGS_PARSEXML_BOTS(MailClients,Mail_Clients)

		//Web applications
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(FileUploads,File_Uploads)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(Unicode,Unicode)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(OutlookWebAccess,Outlook_Web_Access)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(OutlookMobileAccess,Outlook_Mobile_Access)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(ActiveSync,ActiveSync)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(RPCoverHTTP,RPC_over_HTTP)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(FrontpageExtensions,Frontpage_Extensions)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(Coldfusion,Coldfusion)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(WebDAV,WebDAV)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(IISADMPWD,IISADMPWD)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(SharePointPortalServer,SharePoint_Portal_Server)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(SharePointTeamServices,SharePoint_Team_Services)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(SharePointOffice2007,SharePoint_Office_2007)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(TeamFoundationServer,Team_Foundation_Server)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(VirtualServer2005,Virtual_Server_2005)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(CertificateServices,Certificate_Services)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(BizTalkServer,BizTalk_Server)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(CommerceServer,Commerce_Server)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(SmallBusinessServer,Small_Business_Server)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(ASP,ASP)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(ASPNET,ASP_NET)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(ASPNETMVC,ASP_NET_MVC)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(PHP,PHP)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(BITS,BITS)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(SOAP,SOAP)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(JSON,JSON)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(REST,REST)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(WinRM,WinRM)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(WebSocket,WebSocket)
		CWEBKNIGHTSSETTINGS_PARSEXML_WEBAPPS(PaypalIPN,Paypal_IPN)
		else
			{
#ifdef TESTBUILD
				CLogger test("C:\\Debug\\WebKnightSettings\\");
				test.NewEntry(name);
				test.Append(val);
				test.Flush();
#endif
				return false;
			}
	}
	return true;
}

void CWebKnightSettings::LoadAgents()
{
#define CWEBKNIGHTSETTINGS_LOADROBOTS(name) if(Agents.Block##name){\
	if(!Agents.AgentList.##name.UserAgent.IsEmpty()){\
		if(UserAgent.DenyUserAgents.Action==Action::Disabled) UserAgent.DenyUserAgents.Action=Action::Block;\
	}\
	if(!Agents.AgentList.##name.UserAgentSequences.IsEmpty()){\
		if(UserAgent.DenySequences.Action==Action::Disabled) UserAgent.DenySequences.Action=Action::Block;\
	}\
	if(!Agents.AgentList.##name.IP.IsEmpty()){\
		Connection.DenyAddresses.Enabled = true;\
	}\
	AddNotInList(UserAgent.DenyUserAgents.List,Agents.AgentList.##name.UserAgent);\
	AddNotInListLCase(UserAgent.DenySequences.List,Agents.AgentList.##name.UserAgentSequences);\
	AddNotInList(Connection.DenyAddresses.List,Agents.AgentList.##name.IP);}

	//BOTS DATABASE
	CWEBKNIGHTSETTINGS_LOADROBOTS(DataMiningCommercial)
	CWEBKNIGHTSETTINGS_LOADROBOTS(DataMiningPublic)
	CWEBKNIGHTSETTINGS_LOADROBOTS(DownloadManagers)
	CWEBKNIGHTSETTINGS_LOADROBOTS(EmailHarvesting)
	CWEBKNIGHTSETTINGS_LOADROBOTS(GuestbookSpammers)
	CWEBKNIGHTSETTINGS_LOADROBOTS(HackTools)
	CWEBKNIGHTSETTINGS_LOADROBOTS(ImageDownloaders)
	CWEBKNIGHTSETTINGS_LOADROBOTS(Indexing)
	CWEBKNIGHTSETTINGS_LOADROBOTS(Monitoring)
	CWEBKNIGHTSETTINGS_LOADROBOTS(OfflineBrowsers)
	CWEBKNIGHTSETTINGS_LOADROBOTS(OtherBad)
	CWEBKNIGHTSETTINGS_LOADROBOTS(Trademark)
	CWEBKNIGHTSETTINGS_LOADROBOTS(ValidationTools)
	CWEBKNIGHTSETTINGS_LOADROBOTS(LinkChecking)
	CWEBKNIGHTSETTINGS_LOADROBOTS(Browsers)
	CWEBKNIGHTSETTINGS_LOADROBOTS(MediaPlayers)
	CWEBKNIGHTSETTINGS_LOADROBOTS(Proxies)
	CWEBKNIGHTSETTINGS_LOADROBOTS(Adware)
	CWEBKNIGHTSETTINGS_LOADROBOTS(BrowserExtensions)
	CWEBKNIGHTSETTINGS_LOADROBOTS(Spyware)
	CWEBKNIGHTSETTINGS_LOADROBOTS(Editing)
	//CWEBKNIGHTSETTINGS_LOADROBOTS(Device)
	CWEBKNIGHTSETTINGS_LOADROBOTS(NewsFeed)
	CWEBKNIGHTSETTINGS_LOADROBOTS(SearchEngines)
	CWEBKNIGHTSETTINGS_LOADROBOTS(FilteringSoftware)
	CWEBKNIGHTSETTINGS_LOADROBOTS(SoftwareComponent)
	CWEBKNIGHTSETTINGS_LOADROBOTS(Translation)
	CWEBKNIGHTSETTINGS_LOADROBOTS(SEO)
	CWEBKNIGHTSETTINGS_LOADROBOTS(MailClients)
}

bool CWebKnightSettings::ApplyConstraints()
{
	return CHTTPFirewallSettings::ApplyConstraints();
}

CString CWebKnightSettings::ToXML()
{
	CString xml;

	CWebKnightSettings d; //defaults
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

	xml += GetXMLWebRobots(d);	//web robots
	
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
	xml += GetXMLEncodingExploits(d);

	xml += GetXMLWebApplications(d);	//web applications

	return xml;
}

CString CWebKnightSettings::GetXMLWebApplications(CWebKnightSettings& d)
{
#define CWEBKNIGHTSETTINGS_GETXML_WEBAPP(var,name,explanation) \
	xml += 	XML.ToXML("Allow_" #name,"Option",WebApp.Allow_##var?"1":"0",d.WebApp.Allow_##var?"1":"0",explanation);

	CString xml("");
	//Web Applications
	xml += XML.AddSeparator("Web_Applications");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(FileUploads,File_Uploads,"Allows file uploads to your server using the HTTP POST command.")
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(Unicode,Unicode,"Allows Unicode encoding in the urls and other data sent to the server.")
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(OutlookWebAccess,Outlook_Web_Access,"Allows Outlook Web Access. This changes other settings so that OWA is enabled. This reduces the security of your system and it is not recommended that you run OWA as a virtual directory ('/Exchange'). It is better to assign a web site to OWA (Use MMC of Exchange Server: add HTTP server) and exclude this web instance from scanning!")
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(OutlookMobileAccess,Outlook_Mobile_Access,"Allows Outlook Mobile Access. This changes other settings so that OMA is enabled. Outlook Mobile Access is the successor of Mobile Information Server 2002 (MIS) and now comes with Microsoft Exchange Server. It enables access to Exchange Server from XHTML (WAP 2.x), and CHTML-based microbrowsers.")
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(ActiveSync,ActiveSync,"Allows Microsoft ActiveSync. ActiveSync is used for connection with Pocket PCs and similar devices that have Microsoft ActiveSync client software installed. One example is access from Pocket PCs to Exchange Server via Exchange Server ActiveSync.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(RPCoverHTTP,RPC_over_HTTP,"Allows RPC over HTTP Proxy. RPC over HTTP was first introduced in Windows 2003 and Windows XP SP1. It allows RPC connections over an HTTP connection. Exchange 2003 uses this feature for direct remote access from Outlook without a VPN.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(FrontpageExtensions,Frontpage_Extensions,"Allows Frontpage Extensions. This changes other settings so that the firewall will not block Frontpage Extensions. Enabling this reduces the security of your system and make sure you have the latest version of Frontpage installed and keep up with security patches!");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(Coldfusion,Coldfusion,"Allows Coldfusion. This changes other settings so that the firewall will not block these requests. This reduces the security of your system and you should follow security practices of Coldfusion and keep up with security fixes!");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(WebDAV,WebDAV,"Allows WebDAV. WebDAV is an HTTP extension for Distributed Authoring and Versioning. This changes other settings so that the firewall will not block these requests. This reduces the security of your system!");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(IISADMPWD,IISADMPWD,"Allows IISADMPWD. IISADMPWD is a virtual directory that allows users to change their domain/local password over the HTTP protocol. Outlook Web Access can use this feature. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(SharePointPortalServer,SharePoint_Portal_Server,"Allows SharePoint Portal Server. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(SharePointTeamServices,SharePoint_Team_Services,"Allows SharePoint Team Services. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(SharePointOffice2007,SharePoint_Office_2007,"Allows Office SharePoint Server 2007. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(TeamFoundationServer,Team_Foundation_Server,"Allows Team Foundation Server. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(VirtualServer2005,Virtual_Server_2005,"Allows Virtual Server 2005 Web Interface. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(CertificateServices,Certificate_Services,"Allows Certificate Services Web Interface. Certificate Services installs a virtual directory in your default web site for managing certificates via your browser. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(BizTalkServer,BizTalk_Server,"Allows BizTalk Server. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(CommerceServer,Commerce_Server,"Allows Commerce Server. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(SmallBusinessServer,Small_Business_Server,"Allows Small Business Server. This is the same as enabling Outlook Web Access. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(ASP,ASP,"Allows Active Server Pages 3.0 (and previous versions). By default ASP is fully enabled, but if you changed the default settings and disabled ASP then you can use this option to re-enable ASP.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(ASPNET,ASP_NET,"Allows all features of ASP.NET. By default ASP.NET is partially enabled. You should select this option only if you really need debugging, tracing, remoting and SOAP for your ASP.NET.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(ASPNETMVC,ASP_NET_MVC,"Allows ASP.NET MVC. By default ASP.NET MVC is not enabled.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(PHP,PHP,"Allows PHP. Use this to allow PHP isapi extension. This also changes the scanning engine to be compatible with PHP.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(BITS,BITS,"Allows Background Intelligent Transfer Service (BITS). BITS uses an ISAPI to extend IIS to support upload jobs. Use this to enable this isapi extension.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(SOAP,SOAP,"Allows SOAP. By default SOAP is blocked. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(JSON,JSON,"Allows JSON. By default JSON is blocked. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(REST,REST,"Allows REST. By default REST is partially blocked. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(WinRM,WinRM,"Allows Windows Remote Management (WinRM) IIS Extensions. By default WinRM is blocked. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(WebSocket,WebSocket,"Allows WebSocket (RFC 6455). By default WebSocket is blocked. Enabling this changes other settings so that the firewall will not block these requests.");
	CWEBKNIGHTSETTINGS_GETXML_WEBAPP(PaypalIPN,Paypal_IPN,"Allows Paypal IPN. By default Paypal IPN is blocked. Enabling this changes other settings so that the firewall will not block these requests.");
	return xml;
}

CString CWebKnightSettings::GetXMLWebRobots(CWebKnightSettings& d)
{
	CString xml("");
	//BOTS
	xml += XML.AddSeparator("Robots");
	WRITE_XML_BOOL(Robots,AllowRobotsFile,"Allow_Bots_Robots_File","Allow requests for the file 'robots.txt', even for blocked robots. This is recommended because if the file robots.txt cannot be obtained, the robot thinks it has access and you have no other way to tell the robot that it is not allowed.")
	WRITE_XML_BOOL(Robots,Dynamic,"Dynamic_Robots","Requests for robots.txt are executed by a dynamic robots file.")
	WRITE_XML_STRING(Robots,DynamicFile,"Dynamic_Robots_File","The file that gets executed when requesting robots.txt. A sample of such a dynamic file (robots.asp) is included with the installation.")
	WRITE_XML_BOOL(Robots,DenyAll,"Deny_Bots_All","Deny requests from all bots. This is done by looking at the requests for the robots.txt file. Blocking is done by the combination of IP address and User Agent.")
	WRITE_XML_BOOL(Robots,DenyBad,"Deny_Bots_Bad","Deny requests from bad bots. Add the bot trap urls to your robots.txt file (you can find a sample robots.txt with this installation). Now, to lure a bad bot into those urls, add these urls with hidden anchors in your web site (<a href=/badbottrap/></a>). Blocking is done by the combination of IP address and User Agent.")
	WRITE_XML_CSTRINGLIST(Robots,BadBotTraps,"Deny_Bots_BotTraps","Lowercase and no ending slash preferred to catch all the bad bots. Add these urls to your robots.txt:\r\nUser-agent: *\r\nDisallow: /badbottrap/")
	WRITE_XML_CACHE(Robots,DenyAggressive,"Deny_Bots_Aggressive","Deny aggressive bots doing more than a certain amount of requests in a certain amount of time after their initial request for robots.txt.","The amount of requests to block the bot.","The time frame in which the requests are counted (in minutes).")
	WRITE_XML_INT(Robots,BotTimeout,"Deny_Bots_Timeout","The time-out (in hours) to block the bots. Blocking is done by looking at the IP address and User Agent.")

	//BOTS DATABASE
#define CWEBKNIGHTSETTINGS_GETXML_BOTS(var,name,explanation) \
	xml += 	XML.ToXML("Block_Bots_" #name,"Option",Agents.Block##var?"1":"0",d.Agents.Block##var?"1":"0",explanation##" This is done by looking at known user agents and/or IP address defined in Robots.xml.");

	CWEBKNIGHTSETTINGS_GETXML_BOTS(DataMiningCommercial,Data_Mining_Commercial,"Blocks commercial datamining robots.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(DataMiningPublic,Data_Mining_Public,"Blocks non-profit or public datamining robots.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(DownloadManagers,Download_Managers,"Blocks download managers.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(EmailHarvesting,Email_Harvesting,"Blocks email harvesting robots.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(GuestbookSpammers,Guestbook_Spammers,"Blocks guestbook spamming robots.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(HackTools,Hack_Tools,"Blocks certain hacking tools.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(ImageDownloaders,Image_Downloaders,"Blocks image download tools/robots.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(Indexing,Indexing,"Blocks indexing robots.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(Monitoring,Monitoring,"Blocks monitoring robots.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(OfflineBrowsers,Offline_Browsers,"Blocks offline browsers.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(OtherBad,Other_Bad,"Blocks other bad robots.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(Trademark,Trademark,"Blocks copyright/trademark robots.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(ValidationTools,Validation_Tools,"Blocks certain validation tools.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(LinkChecking,Link_Checking,"Blocks URL checking utilities.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(Browsers,Browsers,"Blocks browsers.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(MediaPlayers,Media_Players,"Blocks media players.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(Proxies,Proxies,"Blocks proxy servers.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(Adware,Adware,"Blocks adware.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(BrowserExtensions,Browser_Extensions,"Blocks browser extensions.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(Spyware,Spyware,"Blocks spyware.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(Editing,Editing,"Blocks web/html editing software.")
	//CWEBKNIGHTSETTINGS_GETXML_BOTS(Device,Device,"Blocks devices.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(NewsFeed,News_Feed,"Blocks news feed utilities.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(SearchEngines,Search_Engines,"Blocks search engines.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(FilteringSoftware,Filtering_Software,"Blocks filtering software.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(SoftwareComponent,Software_Component,"Blocks certain software components.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(Translation,Translation,"Blocks translation robots.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(SEO,SEO,"Blocks search engine optimization tools and services.")
	CWEBKNIGHTSETTINGS_GETXML_BOTS(MailClients,Mail_Clients,"Blocks e-mail clients.")

	return xml;
}