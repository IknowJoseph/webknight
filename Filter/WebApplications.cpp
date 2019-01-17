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
#include "StdAfx.h"
#include "WebApplications.h"

CWebApplications::CWebApplications(void)
{
}

CWebApplications::~CWebApplications(void)
{
}

bool CWebApplications::EnableOutlookWebAccess(CWebKnightSettings& Settings)
{
	try{
		//From urlscan and http://support.microsoft.com/default.aspx?scid=kb;EN-US;309508
		EnableWebDAV(Settings); //WebDAV required for OWA

		//Allow all POST sequences
		Settings.Post.EncodingExploits = Action::Disabled;
		Settings.Post.DenySequences.Action = Action::Disabled;

		//2014-04-01 ; 15:21:30 ; W3SVC1 ; OnUrlMap ; 127.0.0.1 ;  ; localhost ;  ; BLOCKED: URL not in allowed list ; c:\inetpub\wwwroot
		//Settings.URL.Allow.Enabled = false;	//fixed empty url issue OnUrlMap in WebKnight 3.2, so this is not needed

		//Allow virtual dirs
		RemoveFrom(Settings.URL.DenySequences.List,"/exchange");
		RemoveFrom(Settings.URL.DenySequences.List,"/public");
		RemoveFrom(Settings.URL.DenySequences.List,"/exadmin");
		RemoveFrom(Settings.URL.DenySequences.List,"/exchweb");
		RemoveFrom(Settings.URL.DenySequences.List,"/bin/");

		//Allow logon form (Exchange 5.5)
		RemoveFrom(Settings.Filename.Deny.List,"logonfrm.asp");
		RemoveFrom(Settings.Filename.Deny.List,"prn");
		RemoveFrom(Settings.Filename.Deny.List,"test.");//test.eml

		//Allow certain paths
		AddNotInList(Settings.Path.AllowPaths.List,"m:\\");
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\exchsrvr\\exchweb");
		AddNotInList(Settings.Path.AllowPaths.List,"\\.\backofficestorage");

		//Allow certain content-types (from testing)
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-UTF8-encoded");
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");
		AddNotInList(Settings.ContentType.Allow.List,"multipart/form-data");

	//EXCHANGE 2000
		//Allow certain settings (from urlscan)
		Settings.Path.Dot = Action::Disabled;				//allow dot in path
		Settings.URL.HighBitShellcode = Action::Disabled;	//allow high bit characters in url
		Settings.URL.AlternateStream = Action::Disabled;	//allow ':' in url
		Settings.Referrer.HighBitShellcode = Action::Disabled;

		//Allow these verbs not in WebDAV (from urlscan)
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POLL");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"POLL");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"BMOVE");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"BMOVE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"BCOPY");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"BCOPY");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"BPROPPATCH");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"BPROPPATCH");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"BDELETE");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"BDELETE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"SUBSCRIBE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"SUBSCRIBE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"UNSUBSCRIBE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"UNSUBSCRIBE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"SUBSCRIPTIONS");RemoveFrom(Settings.Verbs.DenyVerbs.List,"SUBSCRIPTIONS");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"ACL");			RemoveFrom(Settings.Verbs.DenyVerbs.List,"ACL");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"NOTIFY");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"NOTIFY");

		//Allow these filename extensions (from URLScan)
		EnableASP(Settings);
		EnableStaticHTML(Settings);

		//Allow these filename extensions (from testing)
		AddNotInList(Settings.Extensions.Allow.List,".css"); RemoveFrom(Settings.Extensions.Deny.List,".css");
		AddNotInList(Settings.Extensions.Allow.List,".js");  RemoveFrom(Settings.Extensions.Deny.List,".js");
		AddNotInList(Settings.Extensions.Allow.List,".htc"); RemoveFrom(Settings.Extensions.Deny.List,".htc");
		AddNotInList(Settings.Extensions.Allow.List,".xsl"); RemoveFrom(Settings.Extensions.Deny.List,".xsl");
		AddNotInList(Settings.Extensions.Allow.List,".eml"); RemoveFrom(Settings.Extensions.Deny.List,".eml");
		AddNotInList(Settings.Extensions.Allow.List,".wav"); RemoveFrom(Settings.Extensions.Deny.List,".wav");

		//Allow # in url
		Settings.URL.Characters.Value.Remove('#');

		//Allow certain characters in path
		Settings.Path.Characters.Value.Remove(':');
		Settings.Path.Characters.Value.Remove('=');
		Settings.Path.Characters.Value.Remove('+');
		Settings.Path.Characters.Value.Remove('$');
		Settings.Path.Characters.Value.Remove('<');
		Settings.Path.Characters.Value.Remove('>');
		Settings.Path.Characters.Value.Remove('"');
		Settings.Path.Characters.Value.Remove('*');
		Settings.Path.Characters.Value.Remove('|');
		Settings.Path.Characters.Value.Remove('#');
		Settings.Path.Characters.Value.Remove('^');

		//Allow certain characters in filename
		Settings.Filename.Characters.Value.Remove(':');
		Settings.Filename.Characters.Value.Remove('=');
		Settings.Filename.Characters.Value.Remove('+');
		Settings.Filename.Characters.Value.Remove('$');
		Settings.Filename.Characters.Value.Remove('<');
		Settings.Filename.Characters.Value.Remove('>');
		Settings.Filename.Characters.Value.Remove('"');
		Settings.Filename.Characters.Value.Remove('*');
		Settings.Filename.Characters.Value.Remove('|');
		Settings.Filename.Characters.Value.Remove('#');
		Settings.Filename.Characters.Value.Remove('^');

	//EXCHANGE 5.5
		//already in exchange 2000 settings
	
		//EnableIISADMPWD(Settings); (for OWA change password in options - not recommended)

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableOutlookMobileAccess(CWebKnightSettings& Settings)
{
	/* 
	 * Outlook Mobile Access (Exchange 2003), previous called
	 * Microsoft Mobile Information Server 2002
	 * From: http://support.microsoft.com/default.aspx?scid=kb;en-us;823175
	 */
	try{

		//Allow static html
		EnableStaticHTML(Settings);

		//Allow embedded encoding (from EnableOWA()) (TODO: check this)
		Settings.Post.EncodingExploits = Action::Disabled;
		Settings.Post.DenySequences.Action = Action::Disabled;

		//Allow certain verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");			RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"PROPFIND");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"PROPFIND");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"PROPPATCH");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"PROPPATCH");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"DELETE");			RemoveFrom(Settings.Verbs.DenyVerbs.List,"DELETE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"MOVE");			RemoveFrom(Settings.Verbs.DenyVerbs.List,"MOVE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"SEARCH");			RemoveFrom(Settings.Verbs.DenyVerbs.List,"SEARCH");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"X-MS-ENUMATTS");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"X-MS-ENUMATTS");	//Found this also in Exchange 2000 SDK on 04-01-04 (new in Exchange 2000 SP2)

		//Allow certain paths
		AddNotInList(Settings.Path.AllowPaths.List,"m:\\");
		AddNotInList(Settings.Path.AllowPaths.List,"\\.\backofficestorage");
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\exchsrvr\\oma");

		//from urlscan
		Settings.Path.Dot = Action::Disabled;				//allow dot in path
		Settings.URL.HighBitShellcode = Action::Disabled;	//allow high bit characters in url
		Settings.URL.AlternateStream = Action::Disabled;	//allow ':' in url
		Settings.Referrer.HighBitShellcode = Action::Disabled;

		//Allow certain content-types (TODO: check this)
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-UTF8-encoded");
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");
		AddNotInList(Settings.ContentType.Allow.List,"multipart/form-data");

		/*
		TODO: WEBAPP - OWA
		; Deny extensions for Outlook Mobile Access.
		.asax
		.ascs
		.config
		.cs
		.csproj
		.licx
		.pdb
		.resx
		.resources
		.vb
		.vbproj
		.vsdisco
		.webinfo
		.xsd
		.xsx
		//*/

		//Allow # in url
		Settings.URL.Characters.Value.Remove('#');

		//Allow certain characters in path
		Settings.Path.Characters.Value.Remove(':');
		Settings.Path.Characters.Value.Remove('=');
		Settings.Path.Characters.Value.Remove('+');
		Settings.Path.Characters.Value.Remove('$');
		Settings.Path.Characters.Value.Remove('<');
		Settings.Path.Characters.Value.Remove('>');
		Settings.Path.Characters.Value.Remove('"');
		Settings.Path.Characters.Value.Remove('*');
		Settings.Path.Characters.Value.Remove('|');
		Settings.Path.Characters.Value.Remove('#');
		Settings.Path.Characters.Value.Remove('^');

		//Allow certain characters in filename
		Settings.Filename.Characters.Value.Remove(':');
		Settings.Filename.Characters.Value.Remove('=');
		Settings.Filename.Characters.Value.Remove('+');
		Settings.Filename.Characters.Value.Remove('$');
		Settings.Filename.Characters.Value.Remove('<');
		Settings.Filename.Characters.Value.Remove('>');
		Settings.Filename.Characters.Value.Remove('"');
		Settings.Filename.Characters.Value.Remove('*');
		Settings.Filename.Characters.Value.Remove('|');
		Settings.Filename.Characters.Value.Remove('#');
		Settings.Filename.Characters.Value.Remove('^');

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableActiveSync(CWebKnightSettings& Settings)
{
	try{
		/* 
		 * Enables Exchange 2003 ActiveSync
		 * From: http://support.microsoft.com/default.aspx?scid=kb;en-us;823175#1
		 */

		//Allow static html
		EnableStaticHTML(Settings);

		//Allow embedded encoding (from EnableOWA(Settings)) (TODO: check this)
		Settings.Post.EncodingExploits = Action::Disabled;
		Settings.Post.DenySequences.Action = Action::Disabled;

		//https://msdn.microsoft.com/en-us/library/ee160227%28v=exchg.80%29.aspx
		//Settings.EncodingExploits.Regex.RemoveKey("Base64 Payload");

		//ActiveSync
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"PROPFIND");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"PROPFIND");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"PROPPATCH");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"PROPPATCH");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"MKCOL");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"MKCOL");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"DELETE");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"DELETE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"MOVE");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"MOVE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"BMOVE");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"BMOVE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"SEARCH");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"SEARCH");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"PUT");			RemoveFrom(Settings.Verbs.DenyVerbs.List,"PUT");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"OPTIONS");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"OPTIONS");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"X-MS-ENUMATTS");RemoveFrom(Settings.Verbs.DenyVerbs.List,"X-MS-ENUMATTS");	//Found this also in Exchange 2000 SDK on 04-01-04 (new in Exchange 2000 SP2)

		//Allow certain paths
		AddNotInList(Settings.Path.AllowPaths.List,"m:\\");
		AddNotInList(Settings.Path.AllowPaths.List,"\\.\backofficestorage");
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\exchsrvr\\oma\\sync");

		//from urlscan
		Settings.Path.Dot = Action::Disabled;				//allow dot in path
		Settings.URL.HighBitShellcode = Action::Disabled;	//allow high bit characters in url
		Settings.URL.AlternateStream = Action::Disabled;	//allow ':' in url
		Settings.Referrer.HighBitShellcode = Action::Disabled;

		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-UTF8-encoded");
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");
		AddNotInList(Settings.ContentType.Allow.List,"multipart/form-data");

		//Added 2017.01.04 - https://msdn.microsoft.com/en-us/library/ee218447(v=exchg.80).aspx
		AddNotInList(Settings.ContentType.Allow.List,"application/vnd.ms-sync.wbxml");

		//Allow certain attachments
		AddNotInList(Settings.Extensions.Allow.List,".dll"); RemoveFrom(Settings.Extensions.Deny.List,".dll");	//for ActiveSync

		//Allow these filename extensions (TODO: check this)
		AddNotInList(Settings.Extensions.Allow.List,".css"); RemoveFrom(Settings.Extensions.Deny.List,".css");
		AddNotInList(Settings.Extensions.Allow.List,".js");  RemoveFrom(Settings.Extensions.Deny.List,".js");
		AddNotInList(Settings.Extensions.Allow.List,".htc"); RemoveFrom(Settings.Extensions.Deny.List,".htc");
		AddNotInList(Settings.Extensions.Allow.List,".xsl"); RemoveFrom(Settings.Extensions.Deny.List,".xsl");
		AddNotInList(Settings.Extensions.Allow.List,".eml"); RemoveFrom(Settings.Extensions.Deny.List,".eml");
		AddNotInList(Settings.Extensions.Allow.List,".wav"); RemoveFrom(Settings.Extensions.Deny.List,".wav");

		//Allow # in url
		Settings.URL.Characters.Value.Remove('#');

		//Allow certain characters in path
		Settings.Path.Characters.Value.Remove(':');
		Settings.Path.Characters.Value.Remove('=');
		Settings.Path.Characters.Value.Remove('+');
		Settings.Path.Characters.Value.Remove('$');
		Settings.Path.Characters.Value.Remove('<');
		Settings.Path.Characters.Value.Remove('>');
		Settings.Path.Characters.Value.Remove('"');
		Settings.Path.Characters.Value.Remove('*');
		Settings.Path.Characters.Value.Remove('|');
		Settings.Path.Characters.Value.Remove('#');
		Settings.Path.Characters.Value.Remove('^');

		//Allow certain characters in filename
		Settings.Filename.Characters.Value.Remove(':');
		Settings.Filename.Characters.Value.Remove('=');
		Settings.Filename.Characters.Value.Remove('+');
		Settings.Filename.Characters.Value.Remove('$');
		Settings.Filename.Characters.Value.Remove('<');
		Settings.Filename.Characters.Value.Remove('>');
		Settings.Filename.Characters.Value.Remove('"');
		Settings.Filename.Characters.Value.Remove('*');
		Settings.Filename.Characters.Value.Remove('|');
		Settings.Filename.Characters.Value.Remove('#');
		Settings.Filename.Characters.Value.Remove('^');

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableRPCoverHTTP(CWebKnightSettings& Settings)
{
	try{

		//Outlook + Exchange
		Settings.ContentType.MaxContentLength.Value = "1073741824"; //BLOCKED: Content-Length is too long! ; 1073741824
		//MaxURL=16384;
		//MaxQueryString=4096;
		Settings.Post.RFCCompliant = Action::Disabled;

		//Allow virtual dirs
		RemoveFrom(Settings.URL.DenySequences.List,"/rpc");
		//Allow proxy dll
		RemoveFrom(Settings.Filename.Deny.List,"rpcproxy.dll");

		//Allow all post sequences (TODO: check this)
		Settings.Post.EncodingExploits = Action::Disabled;
		Settings.Post.DenySequences.Action = Action::Disabled;

		//allow slow post
		Settings.Global.SlowPostAttack = Action::Disabled;
		
		//Allow certain paths
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\windows\\system32\\rpcproxy");

		//Allow certain verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"RPC_OUT_DATA");RemoveFrom(Settings.Verbs.DenyVerbs.List,"RPC_OUT_DATA");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"RPC_IN_DATA");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"RPC_IN_DATA");

		//Allow certain attachments
		AddNotInList(Settings.Extensions.Allow.List,".dll"); RemoveFrom(Settings.Extensions.Deny.List,".dll");
	
		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableColdfusion(CWebKnightSettings& Settings)
{
	try{

		//extensions
		AddNotInList(Settings.Extensions.Allow.List,".cfm");	RemoveFrom(Settings.Extensions.Deny.List,".cfm");		//ColdFusion
		AddNotInList(Settings.Extensions.Allow.List,".cfml");	RemoveFrom(Settings.Extensions.Deny.List,".cfml");		//ColdFusion

		//Content-Type
		AddNotInList(Settings.ContentType.Allow.List,"application/x-ColdFusion");
		//AddNotInList(Settings.ContentType.Allow.List,"application/x-ColdFusionIDE");

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableFrontpageExtensions(CWebKnightSettings& Settings)
{
	try{
		//From urlscan and: http://support.microsoft.com/default.aspx?scid=kb;EN-US;318290

		//AllowLateScanning (from urlscan)
		Settings.Engine.AllowLateScanning = true;

		//Allow these headers (from urlscan)
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"HEAD");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"HEAD");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"OPTIONS");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"OPTIONS");

		//Allow headers (from URLScan)
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Translate:"); //"Translate:f" means: no script execution (is needed for script source access)

		//Allow certain url sequences (TODO: test this what can be left out?)
		//RemoveFrom(Deny_URL_Sequences,"/_vti_aut");
		//RemoveFrom(Deny_URL_Sequences,"/_vti_bin");
		//RemoveFrom(Deny_URL_Sequences,"/_vti_rpc");
		//RemoveFrom(Deny_URL_Sequences,"/_vti_script");
		//RemoveFrom(Deny_URL_Sequences,"/_mem_bin");
		//RemoveFrom(Deny_URL_Sequences,"/admcgi");
		//RemoveFrom(Deny_URL_Sequences,"/admisapi");
		//RemoveFrom(Deny_URL_Sequences,"/fpdb/");
		//RemoveFrom(Deny_URL_Sequences,"/scripts");

		//Allow certain paths
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\common files\\microsoft shared\\web server extensions");

		//Allow certain filenames (TODO: test this what can be left out?)
		RemoveFrom(Settings.Filename.Deny.List,"_vti_inf.html");
		//RemoveFrom(Settings.Filename.Deny.List,"postinfo.html");  
		//RemoveFrom(Settings.Filename.Deny.List,"fp30reg.dll");	 
		//RemoveFrom(Settings.Filename.Deny.List,"fp4areg.dll");	 
		//RemoveFrom(Settings.Filename.Deny.List,"shtml.dll");		 
		//RemoveFrom(Settings.Filename.Deny.List,"shtml.exe");		 
		//RemoveFrom(Settings.Filename.Deny.List,"fpsrvadm.exe");	 
		//RemoveFrom(Settings.Filename.Deny.List,"fpremadm.exe");	 
		//RemoveFrom(Settings.Filename.Deny.List,"fpadmin.htm");	 
		//RemoveFrom(Settings.Filename.Deny.List,"fpadmcgi.exe");	 
		//RemoveFrom(Settings.Filename.Deny.List,"cfgwiz.exe");	 
		//RemoveFrom(Settings.Filename.Deny.List,"authors.pwd");	 
		//RemoveFrom(Settings.Filename.Deny.List,"author.exe");	 
		//RemoveFrom(Settings.Filename.Deny.List,"author.dll");	 
		//RemoveFrom(Settings.Filename.Deny.List,"administrators.pwd"); 
		//RemoveFrom(Settings.Filename.Deny.List,"access.cnf");	 
		//RemoveFrom(Settings.Filename.Deny.List,"service.cnf");	 
		//RemoveFrom(Settings.Filename.Deny.List,"service.pwd");	 
		//RemoveFrom(Settings.Filename.Deny.List,"service.stp");	 
		//RemoveFrom(Settings.Filename.Deny.List,"services.cnf");	 
		//RemoveFrom(Settings.Filename.Deny.List,"svcacl.cnf");	 
		//RemoveFrom(Settings.Filename.Deny.List,"users.pwd");		 
		//RemoveFrom(Settings.Filename.Deny.List,"writeto.cnf");	 
		//RemoveFrom(Settings.Filename.Deny.List,"dvwssr.dll");	 

		//Allow these filename extensions (from URLScan)
		AddNotInList(Settings.Extensions.Allow.List,".htm"); RemoveFrom(Settings.Extensions.Deny.List,".htm");
		AddNotInList(Settings.Extensions.Allow.List,".html");RemoveFrom(Settings.Extensions.Deny.List,".html");
		AddNotInList(Settings.Extensions.Allow.List,".dll"); RemoveFrom(Settings.Extensions.Deny.List,".dll");

		//Allow content-types:
		AddNotInList(Settings.ContentType.Allow.List,"application/x-vermeer-urlencoded");

		//allow empty URL request (Frontpage 2008 & one previous)
		//Settings.URL.Allow.Action = Action::Disabled;	//fixed null url issue OnUrlMap in WebKnight 3.1, so this is redundant

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableWebDAV(CWebKnightSettings& Settings)
{
	/*
	 * Enable HTTP Extension: WebDAV
	 * See rfc 2518
	 */
	try{
		//Allow WebDAV verbs (from rfc 2518)
		AddNotInList(Settings.Verbs.AllowVerbs.List,"PROPFIND");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"PROPFIND");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"PROPPATCH");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"PROPPATCH");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"MKCOL");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"MKCOL");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");			RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"HEAD");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"HEAD");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"DELETE");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"DELETE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"PUT");			RemoveFrom(Settings.Verbs.DenyVerbs.List,"PUT");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"COPY");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"COPY");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"MOVE");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"MOVE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"LOCK");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"LOCK");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"UNLOCK");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"UNLOCK");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"OPTIONS");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"OPTIONS");

		//Allow MS-WebDAV verbs (from iishelp)
		AddNotInList(Settings.Verbs.AllowVerbs.List,"SEARCH");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"SEARCH");

		//Allow all POST sequences
		Settings.Post.EncodingExploits = Action::Disabled;
		Settings.Post.DenySequences.Action = Action::Disabled;

		//Allow WebDAV headers (from rfc 2518)
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Depth:");
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Destination:");
		RemoveFrom(Settings.Headers.DenyHeaders.List,"If:");
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Lock-Token:");
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Overwrite:");
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Timeout:");
		//Allow MS-WebDAV headers (from testing)
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Translate:"); //"Translate:f" means: no script execution (is needed for script source access)

		//Allow text/xml content type (from rfc 2518);
		AddNotInList(Settings.ContentType.Allow.List,"text/xml");

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableIISADMPWD(CWebKnightSettings& Settings)
{
	try{
		//Allow virtual dir /iisadmpwd
		RemoveFrom(Settings.URL.DenySequences.List,"/iisadmpwd");
		
		//Allow certain filenames
		RemoveFrom(Settings.Filename.Deny.List,"achg.htr");
		RemoveFrom(Settings.Filename.Deny.List,"anot.htr");
		
		//Allow .htr extension
		AddNotInList(Settings.Extensions.Allow.List,".htr"); RemoveFrom(Settings.Extensions.Deny.List,".htr");
		
		//Allow iisadmpwd path
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\winnt\\system32\\inetsrv\\iisadmpwd");

		//Allow certain verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"HEAD");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"HEAD");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");

		//Allow certain content types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableSharePointPortalServer(CWebKnightSettings& Settings)
{
	try{

		EnableWebDAV(Settings);	//uses WebDAV

		//verbs not in WebDAV (from urlscan)
		AddNotInList(Settings.Verbs.AllowVerbs.List,"SUBSCRIBE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"SUBSCRIBE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"INVOKE");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"INVOKE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POLL");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"POLL");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"UNSUBSCRIBE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"INVOKE");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"TRANSLATE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"TRANSLATE");

		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");
		
		//Allow these filename extensions (from URLScan)
		EnableASP(Settings);
		EnableStaticHTML(Settings);

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableSharePointTeamServices(CWebKnightSettings& Settings)
{
	try{

		EnableFrontpageExtensions(Settings);	//uses frontpage

		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");
		
		//Allow these filename extensions (from URLScan)
		EnableASP(Settings);
		EnableStaticHTML(Settings);
		AddNotInList(Settings.Extensions.Allow.List,".htw"); RemoveFrom(Settings.Extensions.Deny.List,".htw");
		AddNotInList(Settings.Extensions.Allow.List,".ida"); RemoveFrom(Settings.Extensions.Deny.List,".ida");
		AddNotInList(Settings.Extensions.Allow.List,".idq"); RemoveFrom(Settings.Extensions.Deny.List,".idq");

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableSharePointOffice2007(CWebKnightSettings& Settings)
{
	try{

		EnableSOAP(Settings); //uses SOAP

		//BLOCKED: Querystring embedded encoding exploit
		Settings.QueryString.EncodingExploits = Action::Disabled;
		Settings.Post.DenySequences.Action = Action::Disabled; //allow upload raw data

		//empty url BLOCKED: URL not in allowed list
		//allow empty URL request
		//Settings.URL.Allow.Action = Action::Disabled;	//fixed null url issue OnUrlMap in WebKnight 3.1, so this is redundant

		//BLOCKED: accessing/running '.axd' file
		AddNotInList(Settings.Extensions.Allow.List,".axd"); RemoveFrom(Settings.Extensions.Deny.List,".axd");

		//URL sequences
		RemoveFrom(Settings.URL.DenySequences.List,"/_vti_bin");
		RemoveFrom(Settings.URL.DenySequences.List,"/_admin/");	//sharepoint admin
		RemoveFrom(Settings.URL.DenySequences.List,"/admin");	//sharepoint admin
		//backup
		RemoveFrom(Settings.URL.DenySequences.List,"/backup");
		Settings.UserAgent.Empty = Action::Disabled;

		//Querystring
		RemoveFrom(Settings.QueryString.DenySequences.List,"=http://");	//sharepoint admin
		RemoveFrom(Settings.QueryString.DenySequences.List,"=https://");	//sharepoint admin

		//EnableWebDAV(Settings);	//uses WebDAV

		////verbs not in WebDAV (from urlscan)
		//AddNotInList(Settings.Verbs.AllowVerbs.List,"SUBSCRIBE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"SUBSCRIBE");
		//AddNotInList(Settings.Verbs.AllowVerbs.List,"INVOKE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"INVOKE");
		//AddNotInList(Settings.Verbs.AllowVerbs.List,"POLL");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"POLL");
		//AddNotInList(Settings.Verbs.AllowVerbs.List,"UNSUBSCRIBE");RemoveFrom(Settings.Verbs.DenyVerbs.List,"INVOKE");
		//AddNotInList(Settings.Verbs.AllowVerbs.List,"TRANSLATE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"TRANSLATE");


		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");
		
		//AllowASP&HTML
		EnableASP(Settings);
		EnableStaticHTML(Settings);

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableTeamFoundationServer(CWebKnightSettings& Settings)
{
	try{

		/* Team Foundation Server 2010:
		BLOCKED: Header 'SOAPAction:' not allowed
		http://microsoft.com/webservices/Connect
		BLOCKED: Content-Type 'application/soap+xml; charset=utf-8' not allowed
		Team Foundation (TFSBuildServiceHost.exe, 10.0.40219.415)
		*/
		EnableSOAP(Settings);
		/*
		/tfs/TeamFoundation/Administration/v3.0/CatalogService.asmx
		BLOCKED: '/admin' not allowed in URL
		C:\Program Files\Microsoft Team Foundation Server 2010\Application Tier\Web Services\TeamFoundation\Administration\v3.0\CatalogService.asmx
		*/
		RemoveFrom(Settings.URL.DenySequences.List,"/admin");	//sharepoint admin
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\microsoft team foundation server");
		/*
		/tfs/SOII201213/VersionControl/v1.0/upload.ashx
		HTTP/1.1
		BLOCKED: Content-Type 'multipart/form-data; boundary=--------------------------8e5m2D6l5Q4h6' not allowed
		Team Foundation (devenv.exe, 11.0.60315.1, Ultimate, SKU:8)
		*/
		EnableFileUploads(Settings);
		/*
		/tfs/projecteni201415/Services/v3.0/LocationService.asmx
		HTTP/1.1
		Team Foundation (devenv.exe, 12.0.21005.1, Pro, SKU:15)
		FedAuth=77u/PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48U2VjdXJpdHlDb250ZXh0VG9rZW4gcDE6SWQ9Il8zMmI0NmY4NS0zODVhLTQzN2ItYTk0NC1hYjliOTdiYWQzN2ItRTIwM0Y4RDk1QjAyQkI0Mjg2REZFNDdBNEQ5RTkxMEQiIHhtbG5zOnAxPSJodHRwOi8vZG9jcy5vYXNpcy1vcGVuLm9yZy93c3MvMjAwNC8wMS9vYXNpcy0yMDA0MDEtd3NzLXdzc2VjdXJpdHktdXRpbGl0eS0xLjAueHNkIiB4bWxucz0iaHR0cDovL2RvY3Mub2FzaXMtb3Blbi5vcmcvd3Mtc3gvd3Mtc2VjdXJlY29udmVyc2F0aW9uLzIwMDUxMiI+PElkZW50aWZpZXI+dXJuOnV1aWQ6MTY0Nzk4OGMtYmIwYS00ZWFhLTg2NTItZDM2NjI0N2Q0YjIxPC9JZGVudGlmaWVyPjxDb29raWUgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwNi8wNS9zZWN1cml0eSI+QjVDMFNWMC9tOUlMeGp1aSs0MUlzWXhibFJmN21qSDVnNlppSW9UVjlyc0FBUUFBWlpKbGo1dTdudzNIMERNUVlSNVFMRENTNGFCby9LaUlrdy91SklmMGpxY25GN09Uek5qQUM2UVNXY1MzQjhVNXR3OFU1b0ZrVXFCa1QxL2J4RkRERVprZk4yTWJZMkJLYlhzYmIrTmF2TVU4Q3Bodm5sK2NxMDRhZ2RlTzhTeTFrbXNNNFpMNWorWWNMR2RJcWpnZkkvVTNOYUJDVGY4Q0cva3dMRnJ1c09OVGxsU1ptbUlXdXpPbkdzeXhFYTRLejllaXJOR2UrdXRmSUFueHBSam1TVk9RTndTSzlZR2tHQUQvQlJncCtYTEJGREF6WGs5dTlzaTdsa2o3cXdMWDRBUXRtaStjZHBPdFI0Mlk0ZjQ2cG14SWNyZ2cwM29aL3VFS3dMNEU1T3NxSkczcDVLR3U4ZDkrcjJlanN3VVEvVGhIbFBraXdVRzZvbm95dHZDa3d3QURBQURUaFQzd0xJNnJURmNDZU5HRXpkMDk5eWJRSCtubmRjYW93d2R1RUZmYjcyd1B6UEN1MGNIaGtueEE2WjBjaFMvMTRwZ3BUMHI0U3pJMXNudUo3UkIrbDZUM2haMElRUHBkYXV0UU52MDhmaWc4TkxEVXlJTjNHZ2l6MmpYTGg0S3B6MnZMZ2EyWXQwOEpjQlViWFV1cFY1SjMrWUJ4cVlqdlFHM3Y1Ry9CKzlmRlJvN3ExdGZqMnhmYzF6b3ZTRExwd0xQK2Uza2ZOMUU0OVJ5R09YalF6VTlkMThBZzRlUkZTRE8zMzVhRDNJWmJzN00wTE8zZC9sU1o1VVVIdHc2OVB6QlBkRFdFSGxDVVIzSDdjcitHSENCMjNyekVXMzdtVVhldGhWNm1xTWtFYUlEZE5jdS91ZG8zVVpYb3g5NFdaM0xsR05Mc09wOXcxMU5pdzBKc2h2SWEvZUxuc05aVERVNEZrcEJrKytmd0kzVjVrMytlVUw4QzNRUmFPalBKQnF6R3pEZW9BSW5GUi8xbno5K3NXd2FjS0ZCTXFrcHBjK0ZMZHVlNzVpbHZwWk96Nzl4V0dVODdYY3ZsWXFMak45TWtOSi9UKzdnMlljZWFiUkRzVjdSODFGTFQ4WE83alhubWtWQVVMRVFsUzliSkI3WE5sc1dJb0c3a01MYjV5RDV2MGhDNGl3eGliTWFYR1pyRjNWNTVEYmxqRGp2L0RaMzN3MGhnblBTaE1hcUhmM1FreS9JU2NrcE1ySjQ5R1Ayd0xkbk1EM29jS0lsbWo3NEpzWU1kOXJjeXlwSnhpWDhucGNKcFUrSEZRSDc1YUZNL0ZremJ3N1pKaWQ5TlFYTGVJRHk3L0oweTRYSnNjQmpaVS8y; FedAuth1=ZGd3NGs2VkNNK0JESnh2RzBkczRlNWtxN25XQ3E2SUQ5NWtxWUwyWnJ6L0RSU094NTVBT1lCQ0JLb3VBUGlDc2c5V3pmYU5iUzJRSXdhVEZHazVmSU9yK3Fzb3RHSW85bmRXZ3UvTVlETlNZTnVLdlkyd1RTY1FBaXhuM0NhY28vS29lTFh2eUNUbEJTS0lGa2FCeDZuSjhSdDFXTmZtUFBBeW5Wa1JTdzVSR1hQT2Q2RTcrekY4cmJPaUdHNTh2aHV3dHdWNSt4K0VzdXFsYWQ2RXppdFNvRVdLTUhETUN2dERyWGp3QmFkeXc3L3d0ZEFWamNMWEhJWjhJQmpCY2FuODRGKzFUb3hmbTJHdUwzUERvL3JNa0REU2tadVFraVFJQ3BxMW9lS3NBYTcxRHJEaGhlalBnYmNwODZqeU4xaWpUSVV2Q0VkZXRuSERTa3RYMzZ1aWwzaFQ1ZSthWjNKVnk5dmx3PTwvQ29va2llPjwvU2VjdXJpdHlDb250ZXh0VG9rZW4+
		BLOCKED: Maximum variable length exceeded in cookie
		*/
		if(Settings.Cookie.MaxVariableLength.Value<2048)
			Settings.Cookie.MaxVariableLength.Value = 2048;

		/*
		/tfs/ProjectenI201415/WorkItemTracking/v4.0/ClientService.asmx
		/tfs/ProjectenI201415/WorkItemTracking/v4.0/ClientService.asmx

		application/soap+xml; charset=utf-8
		BLOCKED: '<meta' not allowed in data
		<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><RequestHeader xmlns="http://schemas.microsoft.com/TeamFoundation/2005/06/WorkItemTracking/ClientServices/03"><Id>uuid:a9b0bff9-1919-4adf-aacf-47a280212ccb</Id></RequestHeader></s:Header><s:Body><GetMetadataEx2 xmlns="http://schemas.microsoft.com/TeamFoundation/2005/06/WorkItemTracking/ClientServices/03"><metadataHave><MetadataTableHaveEntry><RowVersion>111687</RowVersion><TableName>Hierarchy</TableName></MetadataTableHaveEntry><MetadataTableHaveEntry><RowVersion>5163</RowVersion><TableName>Fields</TableName></MetadataTableHaveEntry><MetadataTableHaveEntry><RowVersion>113601</RowVersion><TableName>HierarchyProperties</TableName></MetadataTableHaveEntry><MetadataTableHaveEntry><RowVersion>121019</RowVersion><TableName>Constants</TableName></MetadataTableHaveEntry><MetadataTableHaveEntry><RowVersion>113893</RowVersion><TableName>Rules</TableName></MetadataTableHaveEntry><MetadataTableHaveEntry><RowVersion>121022</RowVersion><TableName>Const
		*/
		RemoveFrom(Settings.Post.DenySequences.List,"<meta");
		
		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableVirtualServer2005(CWebKnightSettings& Settings)
{
try{
		//allow verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");

		//Allow multipart
		AddNotInList(Settings.ContentType.Allow.List,"multipart/form-data");

		//URL sequences
		RemoveFrom(Settings.URL.DenySequences.List,"/scripts"); //for VSScripts.js
		RemoveFrom(Settings.URL.DenySequences.List,"/scripts/");

		//files
		AddNotInList(Settings.Extensions.Allow.List,".cab"); RemoveFrom(Settings.Extensions.Deny.List,".cab"); //for activex
		AddNotInList(Settings.Extensions.Allow.List,".exe"); RemoveFrom(Settings.Extensions.Deny.List,".exe"); //for VSWebApp.exe
	
		//Allow simple HTML
		EnableStaticHTML(Settings);

		return true;
	}catch(...){
		return false;
	}
}


bool CWebApplications::EnableCertificateServices(CWebKnightSettings& Settings)
{
	try{
		//Allow virtual dirs
		RemoveFrom(Settings.URL.DenySequences.List,"/certsrv");
		RemoveFrom(Settings.URL.DenySequences.List,"/certcontrol");
		RemoveFrom(Settings.URL.DenySequences.List,"/certenroll");

		//Allow path
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\winnt\\system32\\certsrv");

		//Allow these verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"HEAD");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"HEAD");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");

		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");
		
		//Allow these filename extensions (from testing)
		EnableASP(Settings);
		AddNotInList(Settings.Extensions.Allow.List,".cer"); RemoveFrom(Settings.Extensions.Deny.List,".cer"); //Certificate (X.509)
		AddNotInList(Settings.Extensions.Allow.List,".gif"); RemoveFrom(Settings.Extensions.Deny.List,".gif");
		AddNotInList(Settings.Extensions.Allow.List,".p7b"); RemoveFrom(Settings.Extensions.Deny.List,".p7b"); //Certificate PKCS#7
		AddNotInList(Settings.Extensions.Allow.List,".pfx"); RemoveFrom(Settings.Extensions.Deny.List,".pfx"); //Certificate PKCS#12
		AddNotInList(Settings.Extensions.Allow.List,".crl"); RemoveFrom(Settings.Extensions.Deny.List,".crl"); //revocation list
		AddNotInList(Settings.Extensions.Allow.List,".crt"); RemoveFrom(Settings.Extensions.Deny.List,".crt"); //authority
		AddNotInList(Settings.Extensions.Allow.List,".cab"); RemoveFrom(Settings.Extensions.Deny.List,".cab");
		AddNotInList(Settings.Extensions.Allow.List,".dll"); RemoveFrom(Settings.Extensions.Deny.List,".dll");

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableBizTalkServer(CWebKnightSettings& Settings)
{
	try{
		EnableWebDAV(Settings); //uses WebDAV

		//Allow virtual dirs
		RemoveFrom(Settings.URL.DenySequences.List,"/biztalkserverdocs");
		RemoveFrom(Settings.URL.DenySequences.List,"/biztalkserverrepository");
		RemoveFrom(Settings.URL.DenySequences.List,"/messagingmanager");
		RemoveFrom(Settings.URL.DenySequences.List,"/biztalktracking");

		//Allow path
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\microsoft biztalk server\\docs");
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\microsoft biztalk server\\biztalkserverrepository");
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\microsoft biztalk server\\messagingmanager");
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\microsoft biztalk server\\biztalktracking");

		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");
		
		//Allow these filename extensions (from research TODO: test this)
		EnableASP(Settings);
		EnableStaticHTML(Settings);
		AddNotInList(Settings.Extensions.Allow.List,".css"); RemoveFrom(Settings.Extensions.Deny.List,".css");
		AddNotInList(Settings.Extensions.Allow.List,".js");  RemoveFrom(Settings.Extensions.Deny.List,".js");
		//AddNotInList(Settings.Extensions.Allow.List,".xsl"); RemoveFrom(Settings.Extensions.Deny.List,".xsl");
		//AddNotInList(Settings.Extensions.Allow.List,".xml"); RemoveFrom(Settings.Extensions.Deny.List,".xml");

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableCommerceServer(CWebKnightSettings& Settings)
{
	try{
		//TODO: WEBAPP - requires SOAP? OWA? WebDAV?
		//TODO: WEBAPP - check all those that are commented out

		//Allow virtual dir
		RemoveFrom(Settings.URL.DenySequences.List,"/widgets");
		//RemoveFrom(Settings.URL.DenySequences.List,"/retail");
		//RemoveFrom(Settings.URL.DenySequences.List,"/retailbizdesk");
		//RemoveFrom(Settings.URL.DenySequences.List,"/supplier");
		
		//Allow certain paths (from research)
		AddNotInList(Settings.Path.AllowPaths.List,"c:\\inetpub\\wwwroot");
		//AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\microsoft commerce server"); //TODO: needed & subdirs?
		//AddNotInList(Settings.Path.AllowPaths.List,"c:\\program files\\microsoft commerce server\\widgets"); //TODO: needed?

		//allow verbs (from urlscan: HEAD not allowed!?)
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"PUT");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"PUT");

		//Allow certain headers (from urlscan)
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Translate:");
		RemoveFrom(Settings.Headers.DenyHeaders.List,"If:");
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Lock-Token:");

		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");
		
		//Allow these filename extensions (from URLScan)
		EnableASP(Settings);
		EnableStaticHTML(Settings);

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableSmallBusinessServer(CWebKnightSettings& Settings)
{
	try{
		EnableOutlookWebAccess(Settings);

		return true;
	}catch(...){
		return false;
	}
}


bool CWebApplications::EnableASPNETMVC(CWebKnightSettings& Settings)
{
	try{
		//allow verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"HEAD");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"HEAD");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");

		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");

		//allow these extensions
		AddNotInList(Settings.Extensions.Allow.List,".aspx");	RemoveFrom(Settings.Extensions.Deny.List,".aspx");

		//Scripts folder
		RemoveFrom(Settings.URL.DenySequences.List,"/scripts");

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableASPNET(CWebKnightSettings& Settings)
{
	try{
		//allow verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"HEAD");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"HEAD");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"DEBUG");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"DEBUG");

		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");

		//enable SOAP
		EnableSOAP(Settings);

		//Allow certain filenames
		RemoveFrom(Settings.Filename.Deny.List,"trace.axd");

		//allow these extensions
		//AddNotInList(Settings.Extensions.Allow.List,".asax");	RemoveFrom(Settings.Extensions.Deny.List,".asax");		//asa
		//AddNotInList(Settings.Extensions.Allow.List,".asa");	RemoveFrom(Settings.Extensions.Deny.List,".asa");			//".asax" contains ".asa"
		//AddNotInList(Settings.Extensions.Allow.List,".ascx");	RemoveFrom(Settings.Extensions.Deny.List,".ascx");		//forbidden by asp.net (custom user controls)
		AddNotInList(Settings.Extensions.Allow.List,".ashx");	RemoveFrom(Settings.Extensions.Deny.List,".ashx");		//custom httphandler
		AddNotInList(Settings.Extensions.Allow.List,".asmx");	RemoveFrom(Settings.Extensions.Deny.List,".asmx");		//web service
		AddNotInList(Settings.Extensions.Allow.List,".aspx");	RemoveFrom(Settings.Extensions.Deny.List,".aspx");		//asp
		AddNotInList(Settings.Extensions.Allow.List,".axd");		RemoveFrom(Settings.Extensions.Deny.List,".axd");			//WebResources (possible information disclosure)
		//AddNotInList(Settings.Extensions.Allow.List,".config");RemoveFrom(Settings.Extensions.Deny.List,".config");		//forbidden by asp.net (config)
		//AddNotInList(Settings.Extensions.Allow.List,".cs");	RemoveFrom(Settings.Extensions.Deny.List,".cs");			//forbidden by asp.net (c#)
		//AddNotInList(Settings.Extensions.Allow.List,".csproj");RemoveFrom(Settings.Extensions.Deny.List,".csproj");		//forbidden by asp.net (c# project)
		//AddNotInList(Settings.Extensions.Allow.List,".licx");	RemoveFrom(Settings.Extensions.Deny.List,".licx");		//forbidden by asp.net (licenses)
		AddNotInList(Settings.Extensions.Allow.List,".rem");		RemoveFrom(Settings.Extensions.Deny.List,".rem");			//remoting
		//AddNotInList(Settings.Extensions.Allow.List,".resources");RemoveFrom(Settings.Extensions.Deny.List,".resources");//forbidden by asp.net (resources)
		//AddNotInList(Settings.Extensions.Allow.List,".resx");	RemoveFrom(Settings.Extensions.Deny.List,".resx");		//forbidden by asp.net (resources in xml file)
		//AddNotInList(Settings.Extensions.Allow.List,".soap");	RemoveFrom(Settings.Extensions.Deny.List,".soap");		//remoting & handling soap requests //done by EnableSOAP()
		//AddNotInList(Settings.Extensions.Allow.List,".vb");	RemoveFrom(Settings.Extensions.Deny.List,".vb");			//forbidden by asp.net (vb code)
		//AddNotInList(Settings.Extensions.Allow.List,".vbproj");RemoveFrom(Settings.Extensions.Deny.List,".vbproj");		//forbidden by asp.net (vb project)
		//AddNotInList(Settings.Extensions.Allow.List,".vsdisco");RemoveFrom(Settings.Extensions.Deny.List,".vsdisco");	//dynamic discovery: security issue!!!! http://msdn.microsoft.com/msdnmag/issues/02/08/XMLFiles/default.aspx
		//AddNotInList(Settings.Extensions.Allow.List,".webinfo");RemoveFrom(Settings.Extensions.Deny.List,".webinfo");	//forbidden by asp.net

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableStaticHTML(CWebKnightSettings& Settings)
{
	try{

		//Allow these verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"HEAD");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"HEAD");
		
		//Allow these extensions
		AddNotInList(Settings.Extensions.Allow.List,".htm"); RemoveFrom(Settings.Extensions.Deny.List,".htm");
		AddNotInList(Settings.Extensions.Allow.List,".html");RemoveFrom(Settings.Extensions.Deny.List,".html");
		AddNotInList(Settings.Extensions.Allow.List,".txt"); RemoveFrom(Settings.Extensions.Deny.List,".txt");
		AddNotInList(Settings.Extensions.Allow.List,".jpg"); RemoveFrom(Settings.Extensions.Deny.List,".jpg");
		AddNotInList(Settings.Extensions.Allow.List,".jpeg");RemoveFrom(Settings.Extensions.Deny.List,".jpeg");
		AddNotInList(Settings.Extensions.Allow.List,".gif"); RemoveFrom(Settings.Extensions.Deny.List,".gif");
		AddNotInList(Settings.Extensions.Allow.List,".png"); RemoveFrom(Settings.Extensions.Deny.List,".png");
		AddNotInList(Settings.Extensions.Allow.List,".ico"); RemoveFrom(Settings.Extensions.Deny.List,".ico");

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableASP(CWebKnightSettings& Settings)
{
	try{

		//Allow these verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"HEAD");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"HEAD");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		//AddNotInList(Settings.Verbs.AllowVerbs.List,"TRACE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"TRACE");

		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");

		//Allow these extensions
		AddNotInList(Settings.Extensions.Allow.List,".asp"); RemoveFrom(Settings.Extensions.Deny.List,".asp");
		AddNotInList(Settings.Extensions.Allow.List,".cer"); RemoveFrom(Settings.Extensions.Deny.List,".cer");
		AddNotInList(Settings.Extensions.Allow.List,".cdx"); RemoveFrom(Settings.Extensions.Deny.List,".cdx");
		//AddNotInList(Settings.Extensions.Allow.List,".asa"); RemoveFrom(Settings.Extensions.Deny.List,".asa");

		return true;
	}catch(...){
		return false;
	}
}


bool CWebApplications::EnablePHP(CWebKnightSettings& Settings)
{
	try{

		//Allow these verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"HEAD");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"HEAD");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		//AddNotInList(Settings.Verbs.AllowVerbs.List,"TRACE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"TRACE");

		//Allow these extensions
		AddNotInList(Settings.Extensions.Allow.List,".php"); RemoveFrom(Settings.Extensions.Deny.List,".php");

		Settings.Engine.IsPHP = true;

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableBITS(CWebKnightSettings& Settings)
{
	try{
		//http://msdn.microsoft.com/en-us/library/windows/desktop/aa362828%28v=vs.85%29.aspx

		//Allow these verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");			RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"HEAD");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"HEAD");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"BITS_POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"BITS_POST");	//BITS uploads

		//Allow certain content-types
		//TODO: WEBAPP - BITS: check list
		AddNotInList(Settings.ContentType.Allow.List,"multipart/byteranges");
		AddNotInList(Settings.ContentType.Allow.List,"multipart/x-byteranges");
	
		//Allow certain headers
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Packet-Type:");				//BITS upload REQUEST/RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Protocol:");					//BITS upload		  RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Session-Id:");				//BITS upload REQUEST/RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Supported-Protocols:");		//BITS upload REQUEST
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Host-Id:");					//BITS upload		  RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Host-Id-Fallback-Timeout:");	//BITS upload		  RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Received-Content-Range:");	//BITS upload		  RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Reply-URL:");				//BITS upload		  RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Error-Code:");				//BITS upload		  RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Error-Context:");			//BITS upload		  RESPONSE

		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Original-Request-URL:");		//BITS Notification REQUEST
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Request-DataFile-Name:");	//BITS Notification REQUEST
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Response-DataFile-Name:");	//BITS Notification REQUEST
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Static-Response-URL:");		//BITS Notification			RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"BITS-Copy-File-To-Destination:");	//BITS Notification			RESPONSE

		RemoveFrom(Settings.Headers.DenyHeaders.List,"Accept-Encoding:");	//BITS REQUEST/RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Content-Name:");		//BITS REQUEST
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Content-Length:");	//BITS REQUEST/RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Content-Range:");		//BITS REQUEST
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Content-Encoding:");	//BITS REQUEST

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableWinRM(CWebKnightSettings& Settings)
{
	try{
		/*
		POST /powershell?serializationLevel=Full;PSVersion=2.0 HTTP/1.1
		User-Agent: Microsoft WinRM Client
		BLOCKED: Content-Type 'application/soap+xml;charset=UTF-8' not allowed
		BLOCKED: User Agent requires at least one of these characters: '/-._'
		BLOCKED: Content-Type 'multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"' not allowed
		*/

		EnableSOAP(Settings);
		//Content-Type
		AddNotInList(Settings.ContentType.Allow.List,"multipart/encrypted");
		//Allow virtual dirs
		RemoveFrom(Settings.URL.DenySequences.List,"/powershell");
		
		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableWebSocket(CWebKnightSettings& Settings)
{
	try{
		/*
			GET /mychat HTTP/1.1
			Host: server.example.com
			Upgrade: websocket
			Connection: Upgrade
			Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
			Sec-WebSocket-Protocol: chat
			Sec-WebSocket-Version: 13
			Origin: http://example.com

			HTTP/1.1 101 Switching Protocols
			Upgrade: websocket
			Connection: Upgrade
			Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=
			Sec-WebSocket-Protocol: chat
		*/

		//allow these headers
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Upgrade:");
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Connection:");
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Origin:");

		RemoveFrom(Settings.Headers.DenyHeaders.List,"Sec-WebSocket-Key:"); 			//WebSocket	REQUEST
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Sec-WebSocket-Extensions:");	//WebSocket	REQUEST/RESPONSE
		//RemoveFrom(Settings.Headers.DenyHeaders.List,"Sec-WebSocket-Accept:");		//WebSocket			RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Sec-WebSocket-Protocol:");		//WebSocket	REQUEST/RESPONSE
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Sec-WebSocket-Version:");		//WebSocket	REQUEST/RESPONSE

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableIPP(CWebKnightSettings& Settings)
{
	try{
		//Internet Printing Protocol

		//Verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");

		//URL
		RemoveFrom(Settings.URL.DenySequences.List,"/ipp");
		RemoveFrom(Settings.URL.DenySequences.List,"/ipp/");

		//Content-Type
		AddNotInList(Settings.ContentType.Allow.List,"application/ipp");

		//Headers
		RemoveFrom(Settings.Headers.DenyHeaders.List,"Transfer-Encoding:");	//Transfer-Encoding: chunked


		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableUnicode(CWebKnightSettings& Settings)
{
	try{

		//MS unicode url encoding (%u)
		RemoveFrom(Settings.EncodingExploits.Keywords,"%u");

		//high bit shellcode
		Settings.URL.HighBitShellcode = Action::Disabled;
		Settings.QueryString.HighBitShellcode = Action::Disabled;
		Settings.Headers.HighBitShellcode = Action::Disabled;
		Settings.Referrer.HighBitShellcode = Action::Disabled;
		Settings.UserAgent.HighBitShellcode = Action::Disabled;
		Settings.Post.HighBitShellcode = Action::Disabled;

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableFileUploads(CWebKnightSettings& Settings)
{
	try{

		//allow verbs
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");

		//Allow certain content-types
		AddNotInList(Settings.ContentType.Allow.List,"application/x-www-form-urlencoded");
		AddNotInList(Settings.ContentType.Allow.List,"multipart/form-data");

		RemoveFrom(Settings.URL.DenySequences.List,"/upload");
		RemoveFrom(Settings.URL.DenySequences.List,"/upfile");
		RemoveFrom(Settings.URL.DenySequences.List,"/upimage");
		RemoveFrom(Settings.URL.DenySequences.List,"/fileupload");

		RemoveFrom(Settings.Filename.Deny.List,"upload");

		RemoveFrom(Settings.QueryString.DenySequences.List,"action=upload");
		RemoveFrom(Settings.QueryString.DenySequences.List,"actiontype=upload");


		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableSOAP(CWebKnightSettings& Settings)
{
	try{

		//VERB
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		//Content-Type
		AddNotInList(Settings.ContentType.Allow.List,"text/xml");
		AddNotInList(Settings.ContentType.Allow.List,"application/soap+xml");
		//Headers
		RemoveFrom(Settings.Headers.DenyHeaders.List,"SOAPAction:");
		//requested files
		AddNotInList(Settings.Extensions.Allow.List,".soap");	RemoveFrom(Settings.Extensions.Deny.List,".soap");		//remoting & handling soap requests

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableJSON(CWebKnightSettings& Settings)
{
	try{

		//VERB
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		//Content-Type
		AddNotInList(Settings.ContentType.Allow.List,"application/json");

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnableREST(CWebKnightSettings& Settings)
{
	try{

		//VERB
		AddNotInList(Settings.Verbs.AllowVerbs.List,"GET");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"GET");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"POST");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"POST");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"PUT");		RemoveFrom(Settings.Verbs.DenyVerbs.List,"PUT");
		AddNotInList(Settings.Verbs.AllowVerbs.List,"DELETE");	RemoveFrom(Settings.Verbs.DenyVerbs.List,"DELETE");

		Settings.Verbs.DenyPayload.Action = Action::Disabled; //Allow payloads for GET requests

		return true;
	}catch(...){
		return false;
	}
}

bool CWebApplications::EnablePaypalIPN(CWebKnightSettings& Settings)
{
	try{

		RemoveFrom(Settings.Post.DenySequences.List,"charset=");

		return true;
	}catch(...){
		return false;
	}
}