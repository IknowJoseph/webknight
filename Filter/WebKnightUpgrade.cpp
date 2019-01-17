#include "StdAfx.h"
#include "WebKnightUpgrade.h"

CWebKnightUpgrade::CWebKnightUpgrade(void)
{
}

CWebKnightUpgrade::~CWebKnightUpgrade(void)
{
}

void CWebKnightUpgrade::Upgrade(CWebKnightSettings& Settings)
{
	//float EPSILON = 0.001f;

	if(Settings.Version < 3.1f)
		InternalUpgrade3_1(Settings);

	if(Settings.Version < 3.2f)
		InternalUpgrade3_2(Settings);

	if(Settings.Version < 3.3f)
		InternalUpgrade3_3(Settings);

	if(Settings.Version < 4.1f)
		InternalUpgrade4_1(Settings);

	if(Settings.Version < 4.2f) //version control was added in 4.2
		InternalUpgrade4_2(Settings);

	if(Settings.Version < 4.3f)
		InternalUpgrade4_3(Settings);

	if(Settings.Version < 4.4f)
		InternalUpgrade4_4(Settings);

	if(Settings.Version < 4.5f)
		InternalUpgrade4_5(Settings);

	if(Settings.Version < 4.6f)
		InternalUpgrade4_6(Settings);

	//TODO: 4.7 - Upgrade
	//if(Settings.Version < 4.7f)
	//	InternalUpgrade4_7(Settings);

	//UPGRADE - add new settings here
}

void CWebKnightUpgrade::InternalUpgrade3_1(CWebKnightSettings& Settings)
{
	Settings.Notify("This configuration file was upgraded to version 3.1");

	Settings.AddNotInMap(Settings.Headers.MaxHeaders.Map,"UA-color:","32");				//nonstandard	REQUEST
	Settings.AddNotInMap(Settings.Headers.MaxHeaders.Map,"UA-CPU:","32");				//nonstandard	REQUEST
	Settings.AddNotInMap(Settings.Headers.MaxHeaders.Map,"UA-OS:","128");				//nonstandard	REQUEST
	Settings.AddNotInMap(Settings.Headers.MaxHeaders.Map,"UA-pixels:","15");				//nonstandard	REQUEST
	Settings.AddNotInMap(Settings.Headers.MaxHeaders.Map,"UA-Voice:","5");				//nonstandard	REQUEST

	Settings.AddNotInMap(Settings.Headers.MaxHeaders.Map,"DNT:","1");					//Do-Not-Track	REQUEST
}

void CWebKnightUpgrade::InternalUpgrade3_2(CWebKnightSettings& Settings)
{
	Settings.Notify("This configuration file was upgraded to version 3.2");

	Settings.ResponseMonitor.SyncServerHeader(true);
	AddNotInList(Settings.HTTPVersion.Allow.List,"HTTP/2.0");
	UpgradeJavaScriptKeywords3_2(Settings.Headers.DenySequences.List);
	UpgradeJavaScriptKeywords3_2(Settings.QueryString.DenySequences.List);
	UpgradeJavaScriptKeywords3_2(Settings.Post.DenySequences.List);
	Settings.AddNotInMap(Settings.Headers.MaxHeaders.Map,"X-Forwarded-For:","8190");		//				REQUEST
}

void CWebKnightUpgrade::InternalUpgrade3_3(CWebKnightSettings& Settings)
{
	Settings.Notify("This configuration file was upgraded to version 3.3");

	AddNotInList(Settings.Authentication.DenyDefaultPasswords.List,"1111");
	AddNotInList(Settings.Authentication.DenyDefaultPasswords.List,"11111");
	AddNotInList(Settings.Authentication.DenyDefaultPasswords.List,"111111");
	AddNotInList(Settings.Authentication.DenyDefaultPasswords.List,"1234");
	AddNotInList(Settings.Authentication.DenyDefaultPasswords.List,"123456");
	AddNotInList(Settings.Authentication.DenyDefaultPasswords.List,"1234567");
	AddNotInList(Settings.Authentication.DenyDefaultPasswords.List,"12345678");
	AddNotInList(Settings.Authentication.DenyDefaultPasswords.List,"123456789");
	AddNotInList(Settings.Authentication.DenyDefaultPasswords.List,"azerty");
	AddNotInList(Settings.Authentication.DenyDefaultPasswords.List,"qwerty");

	//not needed, done by PARSE_XML_RULE_INT_BACKWARDS
	//if(Headers.MaxLength.Value == 0){
	//	Headers.MaxLength.Value = 8192;
	//}
	//if(Global.MaxPostVariableLength.Value == 0){
	//	Global.MaxPostVariableLength.Value = 2048;
	//}
	if(Settings.UserAgent.RequireCharacter.Value == ""){
		Settings.UserAgent.RequireCharacter.Value = "/-._";
	}
	CString val;
	if(Settings.Headers.MaxHeaders.Map.Lookup("Referer:",val)){
		if(val=="1024"){
			Settings.Headers.MaxHeaders.Map.SetAt("Referer:","4095");
		}
	}
}

void CWebKnightUpgrade::InternalUpgrade4_1(CWebKnightSettings& Settings)
{
	Settings.Notify("This configuration file was upgraded to version 4.1");
	//HTTP/2
	//https://http2.github.io/http2-spec/
	Settings.AddNotInMap(Settings.Headers.MaxHeaders.Map,"HTTP2-Settings:","16384"); //multiple of 6 octets (16384 initial value)
	//AddNotInList(Verbs.AllowVerbs,"PRI"); //not used by actual client, but used when server is parsing HTTP/2 request

	//Joe McCray https://www.youtube.com/watch?v=qBVThFwdYTc
	AddNotInList(Settings.Headers.DenySequences.List,"bitsadmin.exe");
	AddNotInList(Settings.QueryString.DenySequences.List,"bitsadmin.exe");
	AddNotInList(Settings.Post.DenySequences.List,"bitsadmin.exe");
	AddNotInList(Settings.Filename.Deny.List,"bitsadmin.exe");
	AddNotInList(Settings.Headers.DenySequences.List,"powershell.exe");
	AddNotInList(Settings.QueryString.DenySequences.List,"powershell.exe");
	AddNotInList(Settings.Post.DenySequences.List,"powershell.exe");
	AddNotInList(Settings.Filename.Deny.List,"powershell.exe");
	AddNotInList(Settings.Headers.DenySequences.List,"wmic.exe");
	AddNotInList(Settings.QueryString.DenySequences.List,"wmic.exe");
	AddNotInList(Settings.Post.DenySequences.List,"wmic.exe");
	AddNotInList(Settings.Filename.Deny.List,"wmic.exe");
	AddNotInList(Settings.Headers.DenySequences.List,"web.config");
	AddNotInList(Settings.QueryString.DenySequences.List,"web.config");
	AddNotInList(Settings.Post.DenySequences.List,"web.config");
	AddNotInList(Settings.Filename.Deny.List,"web.config");

	AddNotInList(Settings.Headers.DenySequences.List,"cscript.exe");
	AddNotInList(Settings.QueryString.DenySequences.List,"cscript.exe");
	AddNotInList(Settings.Post.DenySequences.List,"cscript.exe");
	AddNotInList(Settings.Filename.Deny.List,"cscript.exe");
	AddNotInList(Settings.Headers.DenySequences.List,"wscript.exe");
	AddNotInList(Settings.QueryString.DenySequences.List,"wscript.exe");
	AddNotInList(Settings.Post.DenySequences.List,"wscript.exe");
	AddNotInList(Settings.Filename.Deny.List,"wscript.exe");

	AddNotInList(Settings.Extensions.Deny.List,".vbe");	//Visual Basic Script (Encrypted)
	AddNotInList(Settings.Extensions.Deny.List,".ws");     //Windows Script
	//AddNotInList(Settings.Extensions.Deny.List,".wsf");    //Windows Script
	//AddNotInList(Settings.Extensions.Deny.List,".wsc");    //Windows Script
	//AddNotInList(Settings.Extensions.Deny.List,".wsh");    //Windows Script
	AddNotInList(Settings.Extensions.Deny.List,".ps1");    //PowerShell
	//AddNotInList(Settings.Extensions.Deny.List,".ps1xml"); //PowerShell
	AddNotInList(Settings.Extensions.Deny.List,".ps2");    //PowerShell
	//AddNotInList(Settings.Extensions.Deny.List,".ps2xml"); //PowerShell
	AddNotInList(Settings.Extensions.Deny.List,".psc1");   //PowerShell
	AddNotInList(Settings.Extensions.Deny.List,".psc2");   //PowerShell
	AddNotInList(Settings.Extensions.Deny.List,".msh");    //Monad Script File (PowerShell)
	//AddNotInList(Settings.Extensions.Deny.List,".msh1");   //Monad Script File (PowerShell)
	//AddNotInList(Settings.Extensions.Deny.List,".msh2");   //Monad Script File (PowerShell)
	//AddNotInList(Settings.Extensions.Deny.List,".mshxml"); //Monad Script File (PowerShell)
	//AddNotInList(Settings.Extensions.Deny.List,".msh1xml");//Monad Script File (PowerShell)
	//AddNotInList(Settings.Extensions.Deny.List,".msh2xml");//Monad Script File (PowerShell)

	AddNotInList(Settings.SQLi.Keywords,"||");
	AddNotInList(Settings.SQLi.Keywords,"&&");
	AddNotInList(Settings.SQLi.Keywords,"char(60)"); //stored XSS <;
	AddNotInList(Settings.SQLi.Keywords,"char(62)"); //stored XSS >;

	InternalUpgrade3_3(Settings);
}

void CWebKnightUpgrade::InternalUpgrade4_2(CWebKnightSettings& Settings)
{
	Settings.Notify("This configuration file was upgraded to version 4.2");

	AddNotInList(Settings.URL.DenySequences.List,"/fckeditor");
}

void CWebKnightUpgrade::InternalUpgrade4_3(CWebKnightSettings& Settings)
{
	Settings.Notify("This configuration file was upgraded to version 4.3");

	UpgradeJavaScriptKeywords4_3(Settings.Headers.DenySequences.List);
	UpgradeJavaScriptKeywords4_3(Settings.QueryString.DenySequences.List);
	UpgradeJavaScriptKeywords4_3(Settings.Post.DenySequences.List);

	Settings.RemoveFrom(Settings.QueryString.DenySequences.List,"%u");
	Settings.RemoveFrom(Settings.Headers.DenySequences.List,"%u");
	Settings.RemoveFrom(Settings.Post.DenySequences.List,"%u");

	if(Settings.Agents.BlockOtherBad)
		Settings.Agents.BlockHackTools = true;

	//SQL Keywords
	Settings.RemoveFrom(Settings.SQLi.Keywords, "= !("); //is now detected by "=!("
	AddNotInList(Settings.SQLi.Keywords,"' and '");
	AddNotInList(Settings.SQLi.Keywords,"'and '");
	AddNotInList(Settings.SQLi.Keywords,"'and'");
	AddNotInList(Settings.SQLi.Keywords,"' and'");
	AddNotInList(Settings.SQLi.Keywords,"and 1 --");
	AddNotInList(Settings.SQLi.Keywords,"and 1--");
	AddNotInList(Settings.SQLi.Keywords,"and 1=");
	AddNotInList(Settings.SQLi.Keywords,"' like '");
	AddNotInList(Settings.SQLi.Keywords,"'like '");
	AddNotInList(Settings.SQLi.Keywords,"'like'");
	AddNotInList(Settings.SQLi.Keywords,"' like'");
	AddNotInList(Settings.SQLi.Keywords,"1 like 1");
	AddNotInList(Settings.SQLi.Keywords,"' between '");
	AddNotInList(Settings.SQLi.Keywords,"'between '");
	AddNotInList(Settings.SQLi.Keywords,"'between'");
	AddNotInList(Settings.SQLi.Keywords,"' between'");
	AddNotInList(Settings.SQLi.Keywords,"1 between 1 and 1");
	AddNotInList(Settings.SQLi.Keywords,"'='");
	AddNotInList(Settings.SQLi.Keywords,"'<'");
	AddNotInList(Settings.SQLi.Keywords,"'>'");
	AddNotInList(Settings.SQLi.Keywords,"'<>'");
	AddNotInList(Settings.SQLi.Keywords,"'!='");
	AddNotInList(Settings.SQLi.Keywords,"'<='");
	AddNotInList(Settings.SQLi.Keywords,"'>='");
	AddNotInList(Settings.SQLi.Keywords,"'!<'");
	AddNotInList(Settings.SQLi.Keywords,"'!>'");

	AddNotInList(Settings.SQLi.Keywords,"1'='1");
	//AddNotInList(Settings.SQLi.Keywords,"1=1"); //dangerous to block this one
	AddNotInList(Settings.SQLi.Keywords,"1<1");
	AddNotInList(Settings.SQLi.Keywords,"1>1");
	AddNotInList(Settings.SQLi.Keywords,"1<>1");
	AddNotInList(Settings.SQLi.Keywords,"1!=1");
	AddNotInList(Settings.SQLi.Keywords,"1<=1");
	AddNotInList(Settings.SQLi.Keywords,"1>=1");
	AddNotInList(Settings.SQLi.Keywords,"1!<1");
	AddNotInList(Settings.SQLi.Keywords,"1!>1");

	AddNotInList(Settings.SQLi.Keywords,"chr(");
	AddNotInList(Settings.SQLi.Keywords,"charindex(");
	AddNotInList(Settings.SQLi.Keywords,"concat(");
	AddNotInList(Settings.SQLi.Keywords,"convert(");
	AddNotInList(Settings.SQLi.Keywords,"substring(");
	AddNotInList(Settings.SQLi.Keywords,"left(");
	AddNotInList(Settings.SQLi.Keywords,"mid(");
	AddNotInList(Settings.SQLi.Keywords,"right(");
	AddNotInList(Settings.SQLi.Keywords,"length(");

	AddNotInList(Settings.SQLi.Keywords,"all(");
	AddNotInList(Settings.SQLi.Keywords,"any(");
	AddNotInList(Settings.SQLi.Keywords,"some(");

	//aggregate functions
	AddNotInList(Settings.SQLi.Keywords,"avg(");
	AddNotInList(Settings.SQLi.Keywords,"count(");
	AddNotInList(Settings.SQLi.Keywords,"max(");
	AddNotInList(Settings.SQLi.Keywords,"min(");
	AddNotInList(Settings.SQLi.Keywords,"sum(");

	Settings.ReplaceKeyword(Settings.SQLi.Keywords,"select","select ");
	Settings.ReplaceKeyword(Settings.SQLi.Keywords,"update","update ");
	Settings.ReplaceKeyword(Settings.SQLi.Keywords,"insert","insert ");
	Settings.ReplaceKeyword(Settings.SQLi.Keywords,"delete","delete ");
	Settings.ReplaceKeyword(Settings.SQLi.Keywords,"table "," table ");
	AddNotInList(Settings.SQLi.Keywords,"select(");
	AddNotInList(Settings.SQLi.Keywords,"update(");
	AddNotInList(Settings.SQLi.Keywords,"insert(");
	AddNotInList(Settings.SQLi.Keywords,"delete(");
	AddNotInList(Settings.SQLi.Keywords,"exists(");
	AddNotInList(Settings.SQLi.Keywords,"drop(");
	AddNotInList(Settings.SQLi.Keywords,"alter(");
	AddNotInList(Settings.SQLi.Keywords,"create(");
	AddNotInList(Settings.SQLi.Keywords,"backup(");
	AddNotInList(Settings.SQLi.Keywords,"from(");
	AddNotInList(Settings.SQLi.Keywords,"where(");
	AddNotInList(Settings.SQLi.Keywords,"having(");
	AddNotInList(Settings.SQLi.Keywords,"union(");
	AddNotInList(Settings.SQLi.Keywords,"intersect ");
	AddNotInList(Settings.SQLi.Keywords,"intersect(");
	AddNotInList(Settings.SQLi.Keywords,"except ");
	AddNotInList(Settings.SQLi.Keywords,"except(");
	AddNotInList(Settings.SQLi.Keywords,"not in(");
	AddNotInList(Settings.SQLi.Keywords," in(");

	AddNotInList(Settings.SQLi.Keywords,"'a=0");
	AddNotInList(Settings.SQLi.Keywords,"'0x");
	AddNotInList(Settings.SQLi.Keywords,"[sqlinjection]");
	AddNotInList(Settings.SQLi.Keywords,"[sql injection]");
	AddNotInList(Settings.SQLi.Keywords,"[sqli]");
	AddNotInList(Settings.SQLi.Keywords,"id='");

	AddNotInList(Settings.SQLi.Keywords,"column_name");
	AddNotInList(Settings.SQLi.Keywords,"table_name");

	AddNotInList(Settings.SQLi.Keywords,"benchmark(");
	AddNotInList(Settings.SQLi.Keywords,"coalesce(");
	AddNotInList(Settings.SQLi.Keywords,"database()");
	AddNotInList(Settings.SQLi.Keywords,"schema()");
	AddNotInList(Settings.SQLi.Keywords,"dbms_pipe.receive_message");
	AddNotInList(Settings.SQLi.Keywords,"hex(");
	AddNotInList(Settings.SQLi.Keywords,"load_file(");
	AddNotInList(Settings.SQLi.Keywords,"name_const(");
	AddNotInList(Settings.SQLi.Keywords,"getdate(");
	AddNotInList(Settings.SQLi.Keywords,"sysdate(");
	AddNotInList(Settings.SQLi.Keywords,"now()");
	AddNotInList(Settings.SQLi.Keywords,"order by");
	AddNotInList(Settings.SQLi.Keywords,"case when");
	AddNotInList(Settings.SQLi.Keywords,"exists ");
	AddNotInList(Settings.SQLi.Keywords,"exists(");
	AddNotInList(Settings.SQLi.Keywords,"user()");
	AddNotInList(Settings.SQLi.Keywords,"version()");
	AddNotInList(Settings.SQLi.Keywords,"sleep(");
	AddNotInList(Settings.SQLi.Keywords,"pg_sleep(");
	AddNotInList(Settings.SQLi.Keywords,"waitfor");
	AddNotInList(Settings.SQLi.Keywords,"waitfor delay");
	AddNotInList(Settings.SQLi.Keywords,"@@datadir");
	AddNotInList(Settings.SQLi.Keywords,"@@hostname");

	//https://dev.mysql.com/doc/refman/5.7/en/control-flow-functions.html
	AddNotInList(Settings.SQLi.Keywords,"if(");
	AddNotInList(Settings.SQLi.Keywords,"ifnull(");
	AddNotInList(Settings.SQLi.Keywords,"nullif(");

	//https://dev.mysql.com/doc/refman/5.7/en/encryption-functions.html
	AddNotInList(Settings.SQLi.Keywords,"encode(");
	AddNotInList(Settings.SQLi.Keywords,"encrypt(");
	AddNotInList(Settings.SQLi.Keywords,"decode(");
	AddNotInList(Settings.SQLi.Keywords,"decrypt(");
	AddNotInList(Settings.SQLi.Keywords,"compress(");
	AddNotInList(Settings.SQLi.Keywords,"md5(");
	AddNotInList(Settings.SQLi.Keywords,"sha(");
	AddNotInList(Settings.SQLi.Keywords,"sha1(");
	AddNotInList(Settings.SQLi.Keywords,"sha2(");
	AddNotInList(Settings.SQLi.Keywords,"sha256(");

	//SQL Server
	AddNotInList(Settings.SQLi.Keywords,"collate database_default");
	AddNotInList(Settings.SQLi.Keywords,"collate sql_");
	AddNotInList(Settings.SQLi.Keywords,"collate windows_");

	//sync with CSignatures::PHPExploits
	Settings.RemoveFrom(Settings.Headers.DenySequences.List,"file=http\\://"); //PHP-Nuke remote file attempt (bad signature)
	Settings.RemoveFrom(Settings.Post.DenySequences.List,"file=http\\://");
	AddNotInList(Settings.Headers.DenySequences.List, "<?php"); //PHP injection
	Settings.AddAllList("data://");
	Settings.AddAllList("expect://");
	Settings.AddAllList("glob://");
	Settings.AddAllList("ogg://");
	Settings.AddAllList("phar://");
	Settings.AddAllList("php://");
	Settings.AddAllList("rar://");
	Settings.AddAllList("ssh2://");
	Settings.AddAllList("zlib://");
	Settings.AddAllList("phpinfo()");
	Settings.AddAllList("base64_decode(");
	Settings.AddAllList("eval(");
	Settings.AddAllList("exec(");
	Settings.AddAllList("system(");
	Settings.AddAllList("passthru(");
	Settings.AddAllList("${echo");
	Settings.AddAllList("${exit");

	//sync with CSignatures::RemoteFileInclusion
	AddNotInList(Settings.QueryString.DenySequences.List,"=data:");
	AddNotInList(Settings.QueryString.DenySequences.List,"=file://");
	AddNotInList(Settings.QueryString.DenySequences.List,"=ftp://");
	AddNotInList(Settings.QueryString.DenySequences.List,"=gopher://");
	AddNotInList(Settings.QueryString.DenySequences.List,"=[data:");
	AddNotInList(Settings.QueryString.DenySequences.List,"=[file://");
	AddNotInList(Settings.QueryString.DenySequences.List,"=[ftp://");
	AddNotInList(Settings.QueryString.DenySequences.List,"=[gopher://");
	AddNotInList(Settings.QueryString.DenySequences.List,"base=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"=test??");	// /common.inc.php?CFG[libdir]=test??
	AddNotInList(Settings.QueryString.DenySequences.List,"doc=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"doc]=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"document=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"document]=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"folder=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"folder]=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"inc=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"inc]=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"_incl=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"_incl]=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"include]=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"main=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"pdf=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"pg=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"style=http://");
	AddNotInList(Settings.QueryString.DenySequences.List,"template=http://");

	AddNotInList(Settings.Post.DenySequences.List,"=data:");
	AddNotInList(Settings.Post.DenySequences.List,"=file://");
	AddNotInList(Settings.Post.DenySequences.List,"=ftp://");
	AddNotInList(Settings.Post.DenySequences.List,"=gopher://");
	AddNotInList(Settings.Post.DenySequences.List,"=[data:");
	AddNotInList(Settings.Post.DenySequences.List,"=[file://");
	AddNotInList(Settings.Post.DenySequences.List,"=[ftp://");
	AddNotInList(Settings.Post.DenySequences.List,"=[gopher://");
	AddNotInList(Settings.Post.DenySequences.List,"base=http://");
	AddNotInList(Settings.Post.DenySequences.List,"=test??");	// /common.inc.php?CFG[libdir]=test??
	AddNotInList(Settings.Post.DenySequences.List,"doc=http://");
	AddNotInList(Settings.Post.DenySequences.List,"doc]=http://");
	AddNotInList(Settings.Post.DenySequences.List,"document=http://");
	AddNotInList(Settings.Post.DenySequences.List,"document]=http://");
	AddNotInList(Settings.Post.DenySequences.List,"folder=http://");
	AddNotInList(Settings.Post.DenySequences.List,"folder]=http://");
	AddNotInList(Settings.Post.DenySequences.List,"inc=http://");
	AddNotInList(Settings.Post.DenySequences.List,"inc]=http://");
	AddNotInList(Settings.Post.DenySequences.List,"_incl=http://");
	AddNotInList(Settings.Post.DenySequences.List,"_incl]=http://");
	AddNotInList(Settings.Post.DenySequences.List,"include]=http://");
	AddNotInList(Settings.Post.DenySequences.List,"main=http://");
	AddNotInList(Settings.Post.DenySequences.List,"pdf=http://");
	AddNotInList(Settings.Post.DenySequences.List,"pg=http://");
	AddNotInList(Settings.Post.DenySequences.List,"style=http://");
	AddNotInList(Settings.Post.DenySequences.List,"template=http://");

	if(Settings.Cookie.DenySequences.Action == Action::Disabled) //Enable RFI scanning for Cookie
		Settings.Cookie.DenySequences.Action = Action::Block;
	CSignatures::RemoteFileInclusion(Settings.Cookie.DenySequences.List);

	//sync with CSignatures::EncodingExploits
	//C-style recursive
	AddNotInList(Settings.EncodingExploits.Keywords,"\\x5C");
	AddNotInList(Settings.EncodingExploits.Keywords,"\\x5c");
	AddNotInList(Settings.EncodingExploits.Keywords,"\\x5Cx5C");
	AddNotInList(Settings.EncodingExploits.Keywords,"\\x5cx5c");
	AddNotInList(Settings.EncodingExploits.Keywords,"\\x5cx5C");
	AddNotInList(Settings.EncodingExploits.Keywords,"\\x5Cx5c");
	AddNotInList(Settings.EncodingExploits.Keywords,"\\o134");
	AddNotInList(Settings.EncodingExploits.Keywords,"\\o134o134");

	Upgrade4_3(Settings);
}

void CWebKnightUpgrade::InternalUpgrade4_4(CWebKnightSettings& Settings)
{
	Settings.Notify("This configuration file was upgraded to version 4.4");
	//re-add (first 6 downloads were with a bad key name, but fixed this the same day)
	BOOL ispresent(FALSE);
	ispresent |= Settings.Headers.DenyRegex.Map.RemoveKey(" href");
	ispresent |= Settings.Headers.DenyRegex.Map.RemoveKey(" src");
	ispresent |= Settings.Headers.DenyRegex.Map.RemoveKey(" href=");
	ispresent |= Settings.Headers.DenyRegex.Map.RemoveKey(" src=");
	ispresent |= Settings.Headers.DenyRegex.Map.RemoveKey(" href=\"http");
	ispresent |= Settings.Headers.DenyRegex.Map.RemoveKey(" src=\"http");
	ispresent |= Settings.QueryString.DenyRegex.Map.RemoveKey(" href");
	ispresent |= Settings.QueryString.DenyRegex.Map.RemoveKey(" src");
	ispresent |= Settings.QueryString.DenyRegex.Map.RemoveKey(" href=");
	ispresent |= Settings.QueryString.DenyRegex.Map.RemoveKey(" src=");
	ispresent |= Settings.QueryString.DenyRegex.Map.RemoveKey(" href=\"http");
	ispresent |= Settings.QueryString.DenyRegex.Map.RemoveKey(" src=\"http");
	ispresent |= Settings.Post.DenyRegex.Map.RemoveKey(" href");
	ispresent |= Settings.Post.DenyRegex.Map.RemoveKey(" src");
	ispresent |= Settings.Post.DenyRegex.Map.RemoveKey(" href=");
	ispresent |= Settings.Post.DenyRegex.Map.RemoveKey(" src=");
	ispresent |= Settings.Post.DenyRegex.Map.RemoveKey(" href=\"http");
	ispresent |= Settings.Post.DenyRegex.Map.RemoveKey(" src=\"http");
	if(ispresent){
		Settings.AddAllRegex("href",		CSignatures::RegexPatternHtmlAttribute("href"));
		Settings.AddAllRegex("src",			CSignatures::RegexPatternHtmlAttribute("src"));
		Settings.AddAllRegex("href http",	CSignatures::RegexPatternHtmlAttribute("href","http"));	
		Settings.AddAllRegex("src http",	CSignatures::RegexPatternHtmlAttribute("src","http"));

		AddNotInList(Settings.QueryString.DenySequences.List,"=[data:");
		AddNotInList(Settings.QueryString.DenySequences.List,"=[file://");
		AddNotInList(Settings.QueryString.DenySequences.List,"=[ftp://");
		AddNotInList(Settings.QueryString.DenySequences.List,"=[gopher://");
		AddNotInList(Settings.Post.DenySequences.List,"=[data:");
		AddNotInList(Settings.Post.DenySequences.List,"=[file://");
		AddNotInList(Settings.Post.DenySequences.List,"=[ftp://");
		AddNotInList(Settings.Post.DenySequences.List,"=[gopher://");
		AddNotInList(Settings.Cookie.DenySequences.List,"=[data:");
		AddNotInList(Settings.Cookie.DenySequences.List,"=[file://");
		AddNotInList(Settings.Cookie.DenySequences.List,"=[ftp://");
		AddNotInList(Settings.Cookie.DenySequences.List,"=[gopher://");
	}else{
		Settings.ReplaceAllRegex("href","<(.)+","<.+?");
		Settings.ReplaceAllRegex("src","<(.)+","<.+?");
		Settings.ReplaceAllRegex("href http","<(.)+","<.+?");
		Settings.ReplaceAllRegex("src http","<(.)+","<.+?");

		Settings.ReplaceAllRegex("href","(\\b|\\r|\\n|\"|\'|\\\\)","(\\b|\\n|[\\f\\v\"\'`/])");
		Settings.ReplaceAllRegex("src","(\\b|\\r|\\n|\"|\'|\\\\)","(\\b|\\n|[\\f\\v\"\'`/])");
		Settings.ReplaceAllRegex("href http","(\\b|\\r|\\n|\"|\'|\\\\)","(\\b|\\n|[\\f\\v\"\'`/])");
		Settings.ReplaceAllRegex("src http","(\\b|\\r|\\n|\"|\'|\\\\)","(\\b|\\n|[\\f\\v\"\'`/])");

		Settings.ReplaceAllRegex("href","(\\b)*","(\\b|\\n|[\\f\\v])*");
		Settings.ReplaceAllRegex("src","(\\b)*","(\\b|\\n|[\\f\\v])*");
		Settings.ReplaceAllRegex("href http","(\\b)*","(\\b|\\n|[\\f\\v])*");
		Settings.ReplaceAllRegex("src http","(\\b)*","(\\b|\\n|[\\f\\v])*");
	}

	//this was in 4_3 upgrade, but web admin replaces it with single space
	Settings.RemoveFrom(Settings.QueryString.DenySequences.List,"               ");
	Settings.RemoveFrom(Settings.URL.DenySequences.List,"               ");

	//RFI remove // after =data: (was in 4_3 upgrade)
	Settings.ReplaceKeyword(Settings.QueryString.DenySequences.List,"=data://","=data:");
	Settings.ReplaceKeyword(Settings.QueryString.DenySequences.List,"=[data://","=[data:");
	Settings.ReplaceKeyword(Settings.Cookie.DenySequences.List,"=data://","=data:");
	Settings.ReplaceKeyword(Settings.Cookie.DenySequences.List,"=[data://","=[data:");
	Settings.ReplaceKeyword(Settings.Post.DenySequences.List,"=data://","=data:");
	Settings.ReplaceKeyword(Settings.Post.DenySequences.List,"=[data://","=[data:");

	AddNotInList(Settings.QueryString.DenySequences.List,"=mhtml:");
	AddNotInList(Settings.QueryString.DenySequences.List,"=[mhtml:");
	AddNotInList(Settings.Cookie.DenySequences.List,"=mhtml:");
	AddNotInList(Settings.Cookie.DenySequences.List,"=[mhtml:");
	AddNotInList(Settings.Post.DenySequences.List,"=mhtml:");
	AddNotInList(Settings.Post.DenySequences.List,"=[mhtml:");

	UpgradeJavaScriptKeywords4_4(Settings.Headers.DenySequences.List);
	UpgradeJavaScriptKeywords4_4(Settings.QueryString.DenySequences.List);
	UpgradeJavaScriptKeywords4_4(Settings.Post.DenySequences.List);

	//Sync with CSignatures::MaliciousHTML
	Settings.AddAllList("urn:schemas-microsoft-com:vml");
	Settings.AddAllList("urn:schemas-microsoft-com:xml-data");
	Settings.AddAllList("<meta");
	Settings.AddAllList("<svg");
	Settings.AddAllList("<base");
	Settings.AddAllList("<input");
	Settings.AddAllList("<maction");
	Settings.AddAllList("<frameset");
	//Settings.AddAllList("<comment"); //not effective on our engine
	//Settings.AddAllList("<!--"); //too restrictive
	Settings.AddAllList("<!--#exec"); //https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
	//Settings.AddAllList("<!["); //used in XML
	//Settings.AddAllList("<![data[");
	Settings.AddAllList("<!doctype");
	Settings.AddAllList("<!entity");
	Settings.AddAllList("<!attlist");
	//Settings.AddAllList("<%"); //false positives
	//Settings.AddAllList("<//"); //false positives
	Settings.AddAllList("@import");
	Settings.AddAllList("-o-link");
	Settings.AddAllList("-o-link-source");
	Settings.AddAllList("<animate");
	Settings.AddAllList("<handler");
	Settings.AddAllList("<listener");
	Settings.AddAllList("<?xml-stylesheet");
	Settings.AddAllList("<onevent");
	Settings.AddAllList("<stylesheet");
	Settings.AddAllList("<eval");
	Settings.AddAllList("<vmlframe");
	Settings.AddAllList("<scriptlet");
	Settings.AddAllList("<import");
	Settings.AddAllList("<?import");
	Settings.AddAllList("view-source:");
	Settings.AddAllList("<event-source");

	//Sync with CSignatures::VBScript
	AddNotInList(Settings.Headers.DenySequences.List,"activexobject");
	AddNotInList(Settings.QueryString.DenySequences.List,"activexobject");
	AddNotInList(Settings.Post.DenySequences.List,"activexobject");
	AddNotInList(Settings.Headers.DenySequences.List,"activexobject");
	AddNotInList(Settings.Headers.DenySequences.List,"vbscript:");
	AddNotInList(Settings.QueryString.DenySequences.List,"vbscript:");
	AddNotInList(Settings.Post.DenySequences.List,"vbscript:");
	AddNotInList(Settings.Headers.DenySequences.List,"vbscript:");

	//Sync with CSignatures::EncodingExploits
	AddNotInList(Settings.EncodingExploits.Keywords,"%u0025");
	AddNotInList(Settings.EncodingExploits.Keywords,"%U00000025");

	//SQL keywords
	//AddNotInList(Settings.SQLi.Keywords,"\"");			//can be used in MySQL and in SQL Server when you set QUOTED_IDENTIFIER OFF (default ON) //but also needed in XML and HTML
	AddNotInList(Settings.SQLi.Keywords,"\" or \"");
	AddNotInList(Settings.SQLi.Keywords,"\"or \"");
	AddNotInList(Settings.SQLi.Keywords,"\"or\"");
	AddNotInList(Settings.SQLi.Keywords,"\" or\"");

	AddNotInList(Settings.SQLi.Keywords,"\" and \"");
	AddNotInList(Settings.SQLi.Keywords,"\"and \"");
	AddNotInList(Settings.SQLi.Keywords,"\"and\"");
	AddNotInList(Settings.SQLi.Keywords,"\" and\"");
	AddNotInList(Settings.SQLi.Keywords,"\" xor \"");
	AddNotInList(Settings.SQLi.Keywords,"\"xor \"");
	AddNotInList(Settings.SQLi.Keywords,"\"xor\"");
	AddNotInList(Settings.SQLi.Keywords,"\" xor\"");

	AddNotInList(Settings.SQLi.Keywords,"\" like \"");
	AddNotInList(Settings.SQLi.Keywords,"\"like \"");
	AddNotInList(Settings.SQLi.Keywords,"\"like\"");
	AddNotInList(Settings.SQLi.Keywords,"\" like\"");
	AddNotInList(Settings.SQLi.Keywords,"\" between \"");
	AddNotInList(Settings.SQLi.Keywords,"\"between \"");
	AddNotInList(Settings.SQLi.Keywords,"\"between\"");
	AddNotInList(Settings.SQLi.Keywords,"\" between\"");

	AddNotInList(Settings.SQLi.Keywords,"\"=\"");
	AddNotInList(Settings.SQLi.Keywords,"\"<\"");
	AddNotInList(Settings.SQLi.Keywords,"\">\"");
	AddNotInList(Settings.SQLi.Keywords,"\"<>\"");
	AddNotInList(Settings.SQLi.Keywords,"\"!=\"");
	AddNotInList(Settings.SQLi.Keywords,"\"<=\"");
	AddNotInList(Settings.SQLi.Keywords,"\">=\"");
	AddNotInList(Settings.SQLi.Keywords,"\"!<\"");
	AddNotInList(Settings.SQLi.Keywords,"\"!>\"");
	AddNotInList(Settings.SQLi.Keywords,"\"+\"");
	AddNotInList(Settings.SQLi.Keywords,"\"<=>\"");
	AddNotInList(Settings.SQLi.Keywords,"1\"=\"1");

	//SQL keywords (from SQLMap tamper scripts)
	AddNotInList(Settings.SQLi.Keywords,"/*!");			//SQLMap modsecurityversioned.py
	AddNotInList(Settings.SQLi.Keywords,"/*!0");		//SQLMap halfversionedmorekeywords.py
	AddNotInList(Settings.SQLi.Keywords,"concat_ws(");	//SQLMap concat2concatws.py

	AddNotInList(Settings.SQLi.Keywords,"locate(");
	AddNotInList(Settings.SQLi.Keywords,"instr(");
	AddNotInList(Settings.SQLi.Keywords,"textpos(");

	//https://dev.mysql.com/doc/refman/5.7/en/comparison-operators.html
	AddNotInList(Settings.SQLi.Keywords,"greatest(");	//SQLMap greatest.py
	AddNotInList(Settings.SQLi.Keywords,"interval(");
	AddNotInList(Settings.SQLi.Keywords,"is null");
	//AddNotInList(Settings.SQLi.Keywords,"is not");	//false positives
	AddNotInList(Settings.SQLi.Keywords,"is not null");
	AddNotInList(Settings.SQLi.Keywords,"isnull(");
	AddNotInList(Settings.SQLi.Keywords,"least(");
	//AddNotInList(Settings.SQLi.Keywords,"not like");	//false positives
	AddNotInList(Settings.SQLi.Keywords,"strcmp(");
	AddNotInList(Settings.SQLi.Keywords,"'+'");
	AddNotInList(Settings.SQLi.Keywords,"'<=>'");
	AddNotInList(Settings.SQLi.Keywords,"1<=>1");
	
	AddNotInList(Settings.SQLi.Keywords,"' xor '");
	AddNotInList(Settings.SQLi.Keywords,"'xor '");
	AddNotInList(Settings.SQLi.Keywords,"'xor'");
	AddNotInList(Settings.SQLi.Keywords,"' xor'");
	AddNotInList(Settings.SQLi.Keywords,"xor 1 --");
	AddNotInList(Settings.SQLi.Keywords,"xor 1--");
	AddNotInList(Settings.SQLi.Keywords,"xor 1=");

	AddNotInList(Settings.SQLi.Keywords,"ascii(");
	AddNotInList(Settings.SQLi.Keywords,"bin(");
	AddNotInList(Settings.SQLi.Keywords,"ord(");
	AddNotInList(Settings.SQLi.Keywords,"substr(");

	//https://dev.mysql.com/doc/refman/5.7/en/xml-functions.html
	AddNotInList(Settings.SQLi.Keywords,"extractvalue(");
	AddNotInList(Settings.SQLi.Keywords,"updatexml(");

	AddNotInList(Settings.SQLi.Keywords,"load data infile");
	AddNotInList(Settings.SQLi.Keywords,"select into outfile");
	AddNotInList(Settings.SQLi.Keywords,"utf_file(");

	AddNotInList(Settings.SQLi.Keywords,"'0=a");
	AddNotInList(Settings.SQLi.Keywords,"'sql");
	AddNotInList(Settings.SQLi.Keywords,"'0having'");			//SQLMap securesphere.py
	AddNotInList(Settings.SQLi.Keywords,"'0having'='0having'");	//SQLMap securesphere.py
	AddNotInList(Settings.SQLi.Keywords,"WCRTESTINPUT");

	AddNotInList(Settings.SQLi.Keywords,"sp_oa");
	AddNotInList(Settings.SQLi.Keywords,"sp_oacreate");
	AddNotInList(Settings.SQLi.Keywords,"sp_oadestroy");
	AddNotInList(Settings.SQLi.Keywords,"sp_oageterrorinfo");
	AddNotInList(Settings.SQLi.Keywords,"sp_oagetproperty");
	AddNotInList(Settings.SQLi.Keywords,"sp_oamethod");
	AddNotInList(Settings.SQLi.Keywords,"sp_oasetproperty");
	AddNotInList(Settings.SQLi.Keywords,"sp_oastop");

	//SQL Server
	AddNotInList(Settings.SQLi.Keywords,"systypes");
	AddNotInList(Settings.SQLi.Keywords,"tempdb..");

	//MS Access - System Tables
	AddNotInList(Settings.SQLi.Keywords,"msysaces"); //MsysACEs
	AddNotInList(Settings.SQLi.Keywords,"msysobjects");
	AddNotInList(Settings.SQLi.Keywords,"msysqueries");
	AddNotInList(Settings.SQLi.Keywords,"msysrelationships");

	//MySQL - System Tables
	AddNotInList(Settings.SQLi.Keywords,"mysql.");
	AddNotInList(Settings.SQLi.Keywords,"mysql.user");
	AddNotInList(Settings.SQLi.Keywords,"mysql.host");
	AddNotInList(Settings.SQLi.Keywords,"mysql.db");

	//Oracle - System Tables
	AddNotInList(Settings.SQLi.Keywords," sys.");
	AddNotInList(Settings.SQLi.Keywords,"sys.all_tables");
	AddNotInList(Settings.SQLi.Keywords,"sys.tab");
	AddNotInList(Settings.SQLi.Keywords,"sys.user_");
	AddNotInList(Settings.SQLi.Keywords,"sys.user_catalog");
	AddNotInList(Settings.SQLi.Keywords,"sys.user_objects");
	AddNotInList(Settings.SQLi.Keywords,"sys.user_tab_columns");
	AddNotInList(Settings.SQLi.Keywords,"sys.user_tables");
	AddNotInList(Settings.SQLi.Keywords,"sys.user_views");

	Settings.Headers.MaxHeaders.Map.RemoveKey("Last-Modified:");

	Upgrade4_4(Settings);
}

void CWebKnightUpgrade::InternalUpgrade4_5(CWebKnightSettings& Settings)
{
	Settings.Notify("This configuration file was upgraded to version 4.5");

	Settings.Cookie.Parameters.NameRequireRegex.Value.Replace("^([a-zA-Z0-9_\\.\\-])+$","^[a-zA-Z0-9_\\.\\-$]+$"); //also allow $ sign for $Version and $Path
	Settings.QueryString.Parameters.NameRequireRegex.Value.Replace("^([a-zA-Z0-9_\\.\\-])+$","^[a-zA-Z0-9_\\.\\-]+$");
	Settings.Post.Parameters.NameRequireRegex.Value.Replace("^([a-zA-Z0-9_\\.\\-])+$","^[a-zA-Z0-9_\\.\\-$]+$"); //also allow $ sign for webforms

	//Credit card information disclosure
	ReplaceKeyword(Settings.ResponseMonitor.InformationDisclosure.Map,"Visa"
		"4\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d",
		"4\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	ReplaceKeyword(Settings.ResponseMonitor.InformationDisclosure.Map,"Mastercard",
		"5\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d",
		"5[1-5]\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	ReplaceKeyword(Settings.ResponseMonitor.InformationDisclosure.Map,"Discover",
		"6011[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d",
		"6((011)|(22\\d)|(4[4-9]\\d)|(5\\d\\d))[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	ReplaceKeyword(Settings.ResponseMonitor.InformationDisclosure.Map,"American Express",
		"3\\d\\d\\d[ \\-]?\\d\\d\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d\\d",
		"3[47]\\d\\d[ \\-]?\\d\\d\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d\\d");
	AddNotInMap(Settings.ResponseMonitor.InformationDisclosure.Map,"JCB","35\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	AddNotInMap(Settings.ResponseMonitor.InformationDisclosure.Map,"China UnionPay","62[0-5]\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");

	
	// /zzz.asp;.jpg
	// https://community.rapid7.com/community/metasploit/blog/2009/12/28/exploiting-microsoft-iis-with-metasploit
	if(Settings.URL.Characters.Value.Find(';')==-1)
		Settings.URL.Characters.Value += ';';
	if(Settings.Filename.Characters.Value.Find(';')==-1)
		Settings.Filename.Characters.Value += ';';	
	if(Settings.Path.Characters.Value.Find(';')==-1)
		Settings.Path.Characters.Value += ';';
	
	UpgradeJavaScriptKeywords4_5(Settings.Headers.DenySequences.List);
	UpgradeJavaScriptKeywords4_5(Settings.QueryString.DenySequences.List);
	UpgradeJavaScriptKeywords4_5(Settings.Post.DenySequences.List);

	//Sync with CSignatures::MaliciousHTML
	Settings.AddAllList("<html");
	Settings.AddAllList("<body");
	Settings.AddAllList("<area");
	Settings.AddAllList("<math");

	Settings.ReplaceAllRegex("<.+?(\\b|\\n|[\\f\\v\"\'`/])","(\\b|\\n|[\\f\\v\"\'`/])");
	Settings.Headers.DenyRegex.Map.RemoveKey("XSS charset"); //Content-Type: text/html; charset=utf-8

	AddNotInList(Settings.SQLi.Keywords,"'&'");

	AddNotInList(Settings.Filename.Deny.List,"copy of "); //on W2003
	AddNotInList(Settings.Filename.Deny.List," - copy.");  //on W7+

	Upgrade4_5(Settings);
}

void CWebKnightUpgrade::InternalUpgrade4_6(CWebKnightSettings& Settings)
{
	Settings.Notify("This configuration file was upgraded to version 4.6");

	Settings.Patches.SetAt("<Content_Type_Max_Length App=","<Content_Type_Max_Length Wizard='Maximum content-length based on content-type is new in version 4.6 and might need some fine-tuning for your environment' App=");

	AddNotInList(Settings.EncodingExploits.Keywords,"%%"); //double encoding
	AddNotInList(Settings.EncodingExploits.Keywords,"&amp;"); //html encoded url not decoded by bot
	AddNotInList(Settings.EncodingExploits.Keywords,"='");
	AddNotInList(Settings.EncodingExploits.Keywords,"'&");
	//AddNotInList(Settings.EncodingExploits.Keywords,"'"); //JavaScript's urlEncode does not encode the single quote

	AddNotInList(Settings.URL.Allow.List,"android-app://");

	//Error Page was in WebKnight 4.5.1 - 4.5.5
	Settings.ReplaceKeyword(Settings.ResponseMonitor.InformationDisclosure.Map,"Error Page","(ODBC)|(JDBC)","(O|JDBC)");
	Settings.ReplaceKeyword(Settings.ResponseMonitor.InformationDisclosure.Map,"Error Page","(mysql_)|(mysqli_)","(mysqli?_)");

	//Error Pages
	CStringList errorpages;
	CSignatures::ErrorPages(errorpages);
	CString pattern = "(" + CStringHelper::ToString(errorpages,")|(") + ")";
	pattern.Replace("(ODBC)|(JDBC)","(O|JDBC)");
	pattern.Replace("(mysql_)|(mysqli_)","(mysqli?_)");
	AddNotInMap(Settings.ResponseMonitor.InformationDisclosure.Map,"Error Page",pattern);

	//empty content type is always allowed in 4.6 - Change in functionality: Content Type is always logged and scanned when not empty and removed from LogClientInfoExtra.
	RemoveFrom(Settings.ContentType.Allow.List,"");

	//block tilde in mapped path and requested file: http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf
	if(Settings.Filename.Characters.Value.Find('~')==-1)
		Settings.Filename.Characters.Value += '~';
	if(Settings.Path.Characters.Value.Find('~')==-1)
		Settings.Path.Characters.Value += '~';

	if(Settings.HTTPVersion.MaxLength.Value==15)
		Settings.HTTPVersion.MaxLength.Value = 8;

	AddNotInList(Settings.UserAgent.CurrentDate.List,"%Y/%m/%d");

	if(Settings.ContentType.Deny.Action==Action::Disabled)
		Settings.ContentType.Deny.Action = Action::Block;
	AddNotInList(Settings.ContentType.Deny.List,"application/x-www-form-urlencoded;");//parameters not allowed for this content type
	AddNotInList(Settings.ContentType.Deny.List,"text/html charset=");
	AddNotInList(Settings.ContentType.Deny.List,"text/html,");
	AddNotInList(Settings.ContentType.Deny.List,"text/html; charset=utf8");
	AddNotInList(Settings.ContentType.Deny.List,"text/html; encoding='utf-8'");
	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; boundary=---------------------------41184676334");  //BOT for JCE
	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; boundary=----------------------------7a22987a9ede");//Joomla exploit
	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; boundary=---------------------------7e116d19044c");//Auto Spider
	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; boundary=---------------------------7dd9a6509ce");//upload exploit
	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; boundary=xYzZY");
	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; boundary=(UploadBoundary)");
	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; boundary=----WebKitFormBoundaryScAb2VeaY3T4kgPd");
	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; Charset=UTF-8; boundary=T0PHackTeam_WEBFuck");

	Upgrade4_6(Settings);
}

void CWebKnightUpgrade::InternalUpgrade4_7(CWebKnightSettings& Settings)
{
	Settings.Notify("This configuration file was upgraded to version 4.7");

	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; boundary=---------------------------4314239228695");
	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; boundary=---------------------------7d529a1d23092a");
	AddNotInList(Settings.ContentType.Deny.List,"multipart/form-data; boundary=------------------------924145cd91f1df83");

	//Was this in 4.4: "Archive files in root","^(http(s)?:(/)+([^/])+)?/(/)*([^/])*[.]((zip)|(r|tar)|((t)?gz)|(7z))");
	/*
		/web.z -> won't be blocked, as regex does not care if it's the end of the url or not and it might generate false positives
		/www.uzip
	*/
	ReplaceKeyword(Settings.URL.DenyRegex.Map,"Archive files in root","(zip)","(u?zip)");
	ReplaceKeyword(Settings.URL.DenyRegex.Map,"Archive files in root","((t)?gz)","(t?gz)");

	//Error page
	Settings.ReplaceKeyword(Settings.ResponseMonitor.InformationDisclosure.Map,"Error Page","(Microsoft VBScript compilation)","(Microsoft VBScript (compilation)|(runtime))");

	Upgrade4_7(Settings);
}

void CWebKnightUpgrade::UpgradeJavaScriptKeywords3_2(CStringList& list)
{
	//add keywords (Reported by Mazin Ahmed)
	AddNotInList(list,"onshow");
	AddNotInList(list,"ontoggle");

	//add keywords (Reported by Rafay Baloch)
	AddNotInList(list,"onbounce");
	AddNotInList(list,"onfinish");
	AddNotInList(list,"onstart");
	AddNotInList(list,"onhashchange");
	AddNotInList(list,"onsearch");
	AddNotInList(list,"onselectionchange");
	AddNotInList(list,"onstop");
	AddNotInList(list,"<isindex");
	AddNotInList(list,"formaction");

	//remove trailing =
	ReplaceKeyword(list,"onabort=","onabort");
	ReplaceKeyword(list,"onactivate=","onactivate");		
	ReplaceKeyword(list,"onafterprint=","onafterprint");		
	ReplaceKeyword(list,"onafterupdate=","onafterupdate");		
	ReplaceKeyword(list,"onbeforeactivate=","onbeforeactivate");	
	ReplaceKeyword(list,"onbeforecopy=","onbeforecopy");		
	ReplaceKeyword(list,"onbeforecut=","onbeforecut");		
	ReplaceKeyword(list,"onbeforepaste=","onbeforepaste");		
	ReplaceKeyword(list,"onbeforedeactivate=","onbeforedeactivate");
	ReplaceKeyword(list,"onbeforeeditfocus=","onbeforeeditfocus");	
	ReplaceKeyword(list,"onbeforeonload=","onbeforeunload");
	ReplaceKeyword(list,"onbeforeunload=","onbeforeunload");
	ReplaceKeyword(list,"onbeforeprint=","onbeforeprint");		
	ReplaceKeyword(list,"onbeforeupdate=","onbeforeupdate");	
	ReplaceKeyword(list,"onblur=","onblur");
	ReplaceKeyword(list,"oncanplay=","oncanplay");			
	ReplaceKeyword(list,"oncanplaythrough=","oncanplaythrough");	
	ReplaceKeyword(list,"oncellchange=","oncellchange");		
	ReplaceKeyword(list,"onchange=","onchange");
	ReplaceKeyword(list,"onclick=","onclick");
	ReplaceKeyword(list,"oncontextmenu=","oncontextmenu");		
	ReplaceKeyword(list,"oncontrolselect=","oncontrolselect");	
	ReplaceKeyword(list,"oncopy=","oncopy");			
	ReplaceKeyword(list,"oncut=","oncut");				
	ReplaceKeyword(list,"ondataavailable=","ondataavailable");	
	ReplaceKeyword(list,"ondatasetchanged=","ondatasetchanged");	
	ReplaceKeyword(list,"ondatasetcomplete=","ondatasetcomplete");	
	ReplaceKeyword(list,"ondblclick=","ondblclick");
	ReplaceKeyword(list,"ondeactivate=","ondeactivate");		
	ReplaceKeyword(list,"ondragdrop=","ondragdrop");
	ReplaceKeyword(list,"ondrag=","ondrag");			
	ReplaceKeyword(list,"ondragend=","ondragend");			
	ReplaceKeyword(list,"ondragenter=","ondragenter");		
	ReplaceKeyword(list,"ondragleave=","ondragleave");		
	ReplaceKeyword(list,"ondragover=","ondragover");		
	ReplaceKeyword(list,"ondragstart=","ondragstart");		
	ReplaceKeyword(list,"ondrop=","ondrop");			
	ReplaceKeyword(list,"ondurationchange=","ondurationchange");	
	ReplaceKeyword(list,"onemptied=","onemptied");			
	ReplaceKeyword(list,"onerror=","onerror");
	ReplaceKeyword(list,"onended=","onended");			
	ReplaceKeyword(list,"onerrorupdate=","onerrorupdate");		
	ReplaceKeyword(list,"onfilterchange=","onfilterchange");	
	ReplaceKeyword(list,"onfocus=","onfocus");
	ReplaceKeyword(list,"onfocusin=","onfocusin");			
	ReplaceKeyword(list,"onfocusout=","onfocusout");		
	ReplaceKeyword(list,"onformchange=","onformchange");		
	ReplaceKeyword(list,"onforminput=","onforminput");		
	ReplaceKeyword(list,"onhaschange=","onhaschange");		
	ReplaceKeyword(list,"onhelp=","onhelp");			
	ReplaceKeyword(list,"oninput=","oninput");			
	ReplaceKeyword(list,"oninvalid=","oninvalid");			
	ReplaceKeyword(list,"onkeydown=","onkeydown");
	ReplaceKeyword(list,"onkeypress=","onkeypress");
	ReplaceKeyword(list,"onkeyup=","onkeyup");
	ReplaceKeyword(list,"onlayoutcomplete=","onlayoutcomplete");	                                    
	ReplaceKeyword(list,"onload=","onload");
	ReplaceKeyword(list,"onloadeddata=","onloadeddata");		
	ReplaceKeyword(list,"onloadedmetadata=","onloadedmetadata");	
	ReplaceKeyword(list,"onloadedstart=","onloadstart");		
	ReplaceKeyword(list,"onlosecapture=","onlosecapture");		
	ReplaceKeyword(list,"onmessage=","onmessage");			
	ReplaceKeyword(list,"onmousedown=","onmousedown");
	ReplaceKeyword(list,"onmouseenter=","onmouseenter");		
	ReplaceKeyword(list,"onmouseleave=","onmouseleave");		
	ReplaceKeyword(list,"onmousemove=","onmousemove");		
	ReplaceKeyword(list,"onmouseout=","onmouseout");
	ReplaceKeyword(list,"onmouseover=","onmouseover");
	ReplaceKeyword(list,"onmouseup=","onmouseup");
	ReplaceKeyword(list,"onmousewheel=","onmousewheel");		
	ReplaceKeyword(list,"onmove=","onmove");
	ReplaceKeyword(list,"onmoveend=","onmoveend");			
	ReplaceKeyword(list,"onmovestart=","onmovestart");		
	ReplaceKeyword(list,"onoffline=","onoffline");			
	ReplaceKeyword(list,"ononline=","ononline");			
	ReplaceKeyword(list,"onpagehide=","onpagehide");		
	ReplaceKeyword(list,"onpageshow=","onpageshow");		
	ReplaceKeyword(list,"onpaste=","onpaste");			
	ReplaceKeyword(list,"onpause=","onpause");			
	ReplaceKeyword(list,"onplay=","onplay");			
	ReplaceKeyword(list,"onplaying=","onplaying");			
	ReplaceKeyword(list,"onpopstate=","onpopstate");		
	ReplaceKeyword(list,"onprogress=","onprogress");		
	ReplaceKeyword(list,"onpropertychange=","onpropertychange");	
	ReplaceKeyword(list,"onratechange=","onratechange");		
	ReplaceKeyword(list,"onreadystatechange=","onreadystatechange");
	ReplaceKeyword(list,"onredo=","onredo");			
	ReplaceKeyword(list,"onreset=","onreset");
	ReplaceKeyword(list,"onresize=","onresize");
	ReplaceKeyword(list,"onresizeend=","onresizeend");		
	ReplaceKeyword(list,"onresizestart=","onresizestart");		
	ReplaceKeyword(list,"onrowenter=","onrowenter");		
	ReplaceKeyword(list,"onrowexit=","onrowexit");			
	ReplaceKeyword(list,"onrowsdelete=","onrowsdelete");		
	ReplaceKeyword(list,"onrowsinserted=","onrowsinserted");	
	ReplaceKeyword(list,"onscroll=","onscroll");			
	ReplaceKeyword(list,"onseeked=","onseeked");			
	ReplaceKeyword(list,"onseeking=","onseeking");			
	ReplaceKeyword(list,"onselect=","onselect");
	ReplaceKeyword(list,"onselectstart=","onselectstart");		
	ReplaceKeyword(list,"onstalled=","onstalled");			
	ReplaceKeyword(list,"onstorage=","onstorage");			
	ReplaceKeyword(list,"onsubmit=","onsubmit");
	ReplaceKeyword(list,"onsuspend=","onsuspend");			
	ReplaceKeyword(list,"ontimeerror=","ontimeerror");		
	ReplaceKeyword(list,"ontimeupdate=","ontimeupdate");		
	ReplaceKeyword(list,"onundo=","onundo");			
	ReplaceKeyword(list,"onunload=","onunload");
	ReplaceKeyword(list,"onvolumechange=","onvolumechange");
	ReplaceKeyword(list,"onwaiting=","onwaiting");
}

void CWebKnightUpgrade::UpgradeJavaScriptKeywords4_3(CStringList& list)
{
	ReplaceKeyword(list,"onloadedstart","onloadstart");

	//add new keywords
	AddNotInList(list,"animationend");
	AddNotInList(list,"animationiteration");
	AddNotInList(list,"animationstart");
	AddNotInList(list,"transitionend");
	AddNotInList(list,"onopen");
	AddNotInList(list,"onwheel");

	AddNotInList(list,"ontouchcancel");
	AddNotInList(list,"ontouchend");
	AddNotInList(list,"ontouchmove");
	AddNotInList(list,"ontouchstart");

	AddNotInList(list,"ondevicelight");
	AddNotInList(list,"ondevicemotion");
	AddNotInList(list,"ondeviceorientation");
	AddNotInList(list,"ondeviceproximity");
	AddNotInList(list,"onuserproximity");

	AddNotInList(list,"onlanguagechange");

	//see: http://boho.or.kr/upload/file/EpF447.pdf
	AddNotInList(list,"&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a"); //html-encode "javascript:"
	AddNotInList(list,"expression(");
}

void CWebKnightUpgrade::UpgradeJavaScriptKeywords4_4(CStringList& list)
{
	//missing event handlers reported by Ashar Javed
	AddNotInList(list,"oncancel");
	AddNotInList(list,"oncuechange");
	AddNotInList(list,"ondragexit");
	AddNotInList(list,"onsort");
	AddNotInList(list,"onautocomplete");
	AddNotInList(list,"onautocompleteerror");
	AddNotInList(list,"onclose");

	//https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
	AddNotInList(list,"onbegin");
	AddNotInList(list,"onend");
	AddNotInList(list,"onmediacomplete");
	AddNotInList(list,"onmediaerror");
	AddNotInList(list,"onoutofsync");
	AddNotInList(list,"onrepeat");
	AddNotInList(list,"onresume");
	AddNotInList(list,"onreverse");
	AddNotInList(list,"onseek");
	AddNotInList(list,"onsyncrestored");
	AddNotInList(list,"ontrackchange");
	AddNotInList(list,"onurlflip");
	AddNotInList(list,"seeksegmenttime");

	AddNotInList(list,"domattrmodified");
	AddNotInList(list,"domcharacterdatamodified");
	AddNotInList(list,"domfocusin");
	AddNotInList(list,"domfocusout");
	AddNotInList(list,"dommousescroll");
	AddNotInList(list,"domnodeinserted");
	AddNotInList(list,"domnodeinsertedintodocument");
	AddNotInList(list,"domnoderemoved");
	AddNotInList(list,"domnoderemovedfromdocument");
	AddNotInList(list,"domsubtreemodified");

	AddNotInList(list,"fromcharcode");
}

void CWebKnightUpgrade::UpgradeJavaScriptKeywords4_5(CStringList& list)
{
	//Howest Honeypot Project 2015
	AddNotInList(list,"onfullscreenchange");
	AddNotInList(list,"onsvgload");
	AddNotInList(list,"onsvgunload");
	AddNotInList(list,"onvisibilitychange");
}

void CWebKnightUpgrade::Upgrade4_3(CWebKnightSettings& Settings)
{
	//URL
	AddNotInList(Settings.URL.DenySequences.List,"/."); //also blocks /.well-known/assetlinks.json
	AddNotInList(Settings.URL.DenySequences.List,"/.config");

	AddNotInList(Settings.URL.DenySequences.List,"/.git");
	AddNotInList(Settings.URL.DenySequences.List,"/.hg");
	AddNotInList(Settings.URL.DenySequences.List,"/.svn");
	AddNotInList(Settings.URL.DenySequences.List,"/cvs/entries");

	AddNotInList(Settings.URL.DenySequences.List,"/.ht");
	AddNotInList(Settings.URL.DenySequences.List,"/.7z");
	AddNotInList(Settings.URL.DenySequences.List,"/.bash_history");

	AddNotInList(Settings.URL.DenySequences.List,"/access_log");
	AddNotInList(Settings.URL.DenySequences.List,"/access_logs/");

	AddNotInList(Settings.URL.DenySequences.List,"/fck/editor");
	AddNotInList(Settings.URL.DenySequences.List,"/fck_2010/editor/filemanager/connectors/asp/connector.asp");

	AddNotInList(Settings.URL.DenySequences.List,"/acunetix-wvs-test-for-some-inexistent-file");
	AddNotInList(Settings.URL.DenySequences.List,"/none_existing_page");
	AddNotInList(Settings.URL.DenySequences.List,"/random_file_name");

	AddNotInList(Settings.URL.DenySequences.List,"/c99");	//remote shell
	AddNotInList(Settings.URL.DenySequences.List,"/c100");	//remote shell
	AddNotInList(Settings.URL.DenySequences.List,"/r57");	//remote shell
	AddNotInList(Settings.URL.DenySequences.List,"/0day");
	AddNotInList(Settings.URL.DenySequences.List,"/0d4y");
	AddNotInList(Settings.URL.DenySequences.List,"/4dm1n");
	AddNotInList(Settings.URL.DenySequences.List,"/shell");

	AddNotInList(Settings.URL.DenySequences.List,"/upload");
	AddNotInList(Settings.URL.DenySequences.List,"/upfile");
	AddNotInList(Settings.URL.DenySequences.List,"/upimage");
	AddNotInList(Settings.URL.DenySequences.List,"/fileupload");

	AddNotInList(Settings.URL.DenySequences.List,"/server-status");	//Apache server modules
	AddNotInList(Settings.URL.DenySequences.List,"/server-info");	//Apache server modules

	AddNotInList(Settings.URL.DenySequences.List,"/notified-lac_compliance"); //spambot

	//AddNotInList(Settings.URL.DenySequences.List,".php/"); //PHP_SELF exploit: https://www.exploit-db.com/exploits/15370/ also used in CodeIgniter, Wikimedia...
	AddNotInList(Settings.URL.DenySequences.List,".php\\"); //PHP_SELF exploit: https://www.exploit-db.com/exploits/15370/
	AddNotInList(Settings.URL.DenySequences.List,".asp/");
	AddNotInList(Settings.URL.DenySequences.List,".asp\\");
	AddNotInList(Settings.URL.DenySequences.List,".aspx/");
	AddNotInList(Settings.URL.DenySequences.List,".aspx\\");

	//Filenames
	AddNotInList(Settings.Filename.Deny.List,"error_log.php");
	AddNotInList(Settings.Filename.Deny.List,"htaccess.txt");
	AddNotInList(Settings.Filename.Deny.List,"awstats.pl");
	AddNotInList(Settings.Filename.Deny.List,"log.phtml");
	AddNotInList(Settings.Filename.Deny.List,"ipn_log.txt"); //paypal ipn log of ipn.php

	AddNotInList(Settings.Filename.Deny.List,"vbseocp.php"); //https://www.globallinuxsecurity.pro/vbulletin-and-vbseo-exploit-attacks-in-the-wild/
	AddNotInList(Settings.Filename.Deny.List,"mime.types");
	AddNotInList(Settings.Filename.Deny.List,"fck_about.html");
	AddNotInList(Settings.Filename.Deny.List,"robots9.txt");
	AddNotInList(Settings.Filename.Deny.List,"sqldnxlpo.html");

	AddNotInList(Settings.Filename.Deny.List,"thumbs.db");		//Windows image file caches
	AddNotInList(Settings.Filename.Deny.List,"ehthumbs.db");	//Windows image file caches
	AddNotInList(Settings.Filename.Deny.List,"desktop.ini");	//Folder config file
	AddNotInList(Settings.Filename.Deny.List,".ds_store");		//Mac desktop service store files

	AddNotInList(Settings.Filename.Deny.List,"cmdasp.asp");		//remote shell
	AddNotInList(Settings.Filename.Deny.List,"shell.php");		//remote shell
	AddNotInList(Settings.Filename.Deny.List,"r57shell.php");	//remote shell
	AddNotInList(Settings.Filename.Deny.List,"~.aspx");			//remote shell
	AddNotInList(Settings.Filename.Deny.List,"nst.php");		//remote shell
	AddNotInList(Settings.Filename.Deny.List,"nstview.php");	//remote shell
	AddNotInList(Settings.Filename.Deny.List,"perl.php");		//remote shell
	AddNotInList(Settings.Filename.Deny.List,"tmp.php");		//remote shell
	AddNotInList(Settings.Filename.Deny.List,"1nj3ct0r.php");	//remote shell

	AddNotInList(Settings.Filename.Deny.List,".php.");
	AddNotInList(Settings.Filename.Deny.List,"phpinfo.php");
	AddNotInList(Settings.Filename.Deny.List,"timthumb.php"); //highly exploitable + no longer maintained

	AddNotInList(Settings.Filename.Deny.List,"upload");

	//Extensions
	AddNotInList(Settings.Extensions.Deny.List,".htconfig");
	AddNotInList(Settings.Extensions.Deny.List,".passwd");
	AddNotInList(Settings.Extensions.Deny.List,".php~");
	AddNotInList(Settings.Extensions.Deny.List,".php-bak");
	AddNotInList(Settings.Extensions.Deny.List,".thumb");

	//Querystring
	AddNotInList(Settings.QueryString.DenySequences.List,"action=upload");
	AddNotInList(Settings.QueryString.DenySequences.List,"actiontype=upload");

	AddNotInList(Settings.QueryString.DenySequences.List," Result:");
	AddNotInList(Settings.URL.DenySequences.List," Result:");

	Settings.AddAllList("shell.txt");
	Settings.AddAllList("/shell.");

	Settings.AddAllList("/bin/");
	Settings.AddAllList("/bin/bash");
	Settings.AddAllList("/dev/");
	Settings.AddAllList("/etc/");
	Settings.AddAllList("/etc/passwd");
	Settings.AddAllList("/proc/");
	Settings.AddAllList("/proc/self/environ");
	Settings.AddAllList("/tmp/");
	Settings.AddAllList("/usr/");
	Settings.AddAllList("/var/");

	if(Settings.QueryString.DenyRegex.Action == Action::Disabled)
		Settings.QueryString.DenyRegex.Action = Action::Block;
	if(Settings.Post.DenyRegex.Action == Action::Disabled)
		Settings.Post.DenyRegex.Action = Action::Block;
	if(Settings.Headers.DenyRegex.Action == Action::Disabled)
		Settings.Headers.DenyRegex.Action = Action::Block;
	Settings.AddAllRegex("href",		CSignatures::RegexPatternHtmlAttribute("href"));
	Settings.AddAllRegex("src",			CSignatures::RegexPatternHtmlAttribute("src"));
	Settings.AddAllRegex("href http",	CSignatures::RegexPatternHtmlAttribute("href","http"));	
	Settings.AddAllRegex("src http",	CSignatures::RegexPatternHtmlAttribute("src","http"));
}

void CWebKnightUpgrade::Upgrade4_4(CWebKnightSettings& Settings)
{
	AddNotInList(Settings.URL.DenySequences.List,"/psdscpullserver.svc");	//Desired State: Compromised (Brucon 2015)

	//deprecated img attributes
	Settings.AddAllRegex("XSS background", CSignatures::RegexPatternHtmlAttribute("background"));
	Settings.AddAllRegex("XSS data", CSignatures::RegexPatternHtmlAttribute("data"));
	Settings.AddAllRegex("XSS dirname", CSignatures::RegexPatternHtmlAttribute("dirname"));
	Settings.AddAllRegex("XSS dynsrc", CSignatures::RegexPatternHtmlAttribute("dynsrc"));
	Settings.AddAllRegex("XSS lowsrc", CSignatures::RegexPatternHtmlAttribute("lowsrc"));
	Settings.AddAllRegex("XSS poster", CSignatures::RegexPatternHtmlAttribute("poster"));
	Settings.AddAllRegex("XSS srcdoc", CSignatures::RegexPatternHtmlAttribute("srcdoc"));
	Settings.AddAllRegex("XSS srcset", CSignatures::RegexPatternHtmlAttribute("srcset"));
	Settings.AddAllRegex("XSS style", CSignatures::RegexPatternHtmlAttribute("style"));
	Settings.AddAllRegex("XSS xlink:actuate","xlink(\\b|\\n|[\\f\\v])*:(\\b|\\n|[\\f\\v])*actuate");
	Settings.AddAllRegex("XSS xlink:href","xlink(\\b|\\n|[\\f\\v])*:(\\b|\\n|[\\f\\v])*href");
	Settings.AddAllRegex("XSS xmlns:xlink","xmlns(\\b|\\n|[\\f\\v])*:(\\b|\\n|[\\f\\v])*xlink");
	Settings.AddAllRegex("XSS name dataurl", CSignatures::RegexPatternHtmlAttribute("name","dataurl"));
	Settings.AddAllRegex("XSS handler", CSignatures::RegexPatternHtmlAttribute("handler"));
	Settings.AddAllRegex("XSS charset", CSignatures::RegexPatternHtmlAttribute("charset"), false);
	Settings.AddAllRegex("XSS dataformatas", CSignatures::RegexPatternHtmlAttribute("dataformatas"));
	Settings.AddAllRegex("XSS datasrc", CSignatures::RegexPatternHtmlAttribute("datasrc"));
	Settings.AddAllRegex("sandbox", CSignatures::RegexPatternHtmlAttribute("sandbox"));

	Settings.AddAllRegex("XSS expression", CSignatures::RegexPatternHtmlEncoded("expression") + "(\\b|\\n|[\\f\\v])*\\("); //<div style="x:e\x\p\r\ession(alert(1))">div</div> //Reported by Ashar Javed
	Settings.AddAllRegex("XSS javascript", CSignatures::RegexPatternHtmlEncoded("javascript:"));
	Settings.AddAllRegex("XSS vbscript",   CSignatures::RegexPatternHtmlEncoded("vbscript:"));
	Settings.AddAllRegex("XSS livescript", CSignatures::RegexPatternHtmlEncoded("livescript:"));

	//deny namespace declarations
	//Settings.AddAllRegex("xmlns", CSignatures::RegexPatternHtmlAttribute("xmlns")); //used in genuine SOAP requests
	Settings.AddAllRegex("XSS xmlns xlink", CSignatures::RegexPatternHtmlAttribute("xmlns","http://www.w3.org/1999/xlink"));
	Settings.AddAllRegex("XSS xmlns svg", CSignatures::RegexPatternHtmlAttribute("xmlns","http://www.w3.org/2000/svg"));
	Settings.AddAllRegex("XSS xmlns xhtml", CSignatures::RegexPatternHtmlAttribute("xmlns","http://www.w3.org/1999/xhtml"));
	Settings.AddAllList("http://www.w3.org/1999/xlink");
	Settings.AddAllList("http://www.w3.org/2000/svg");
	Settings.AddAllList("http://www.w3.org/1999/xhtml");
	Settings.AddAllList("http://www.w3.org/2001/xml-events");
	Settings.AddAllList("http://www.w3.org/1999/XSL/Transform");
	Settings.AddAllList("http://www.wapforum.org/2001/wml");
	Settings.AddAllList("http://www.w3.org/TR/WD-xsl");

	Settings.AddAllList("&tab;");	//j&Tab;avascript:
	Settings.AddAllList("&newline;");
	Settings.AddAllRegex("XSS JavaScript OnEvent",CSignatures::RegexPatternHtmlAttribute("on(\\c)+"));
	Settings.AddAllRegex("JSFuck payload",CStringHelper::Repeat("[+!\\[\\](){}]",20));

	//Allow in headers (X-Client-Data: header of Daumoa (=Chrome?) user agent)
	/*
		GET /useragents/
		Action=ShowAgentDetails&Name=naver-blog+ogcrawler
		HTTP/1.1
		BLOCKED: 'data:' not allowed in headers
		Connection: keep-alive  
		Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*//*;q=0.8  
		Accept-Encoding: gzip, deflate, sdch  
		Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.6,en;q=0.4  
		Host: www.aqtronix.com  
		Referer: https://www.google.co.kr/search?q=user+agent+naver+blog&aqs=chrome..69i57j0l5.1260j0j7&es_sm=93&oq=user+agent+naver+blog&gs_l=heirloom-serp.3...357180.367192.0.367416.32.27.2.3.0.1.190.2659.20j7.27.0....0...1ac.1j4.34.heirloom-serp..7.25.2182.-fzuj7TGmno  
		User-Agent: Mozilla/5.0 (compatible; MSIE or Firefox mutant; not on Windows server;) Daumoa 4.0  
		Upgrade-Insecure-Requests: 1  
		X-Client-Data: CKS2yQEIqbbJAQjEtskBCO2IygEI/ZXKAQiUl8oBCLyYygE=  
		Mozilla/5.0 (compatible; MSIE or Firefox mutant; not on Windows server;) Daumoa 4.0
		https://www.google.co.kr/search?q=user+agent+naver+blog&aqs=chrome..69i57j0l5.1260j0j7&es_sm=93&oq=user+agent+naver+blog&gs_l=heirloom-serp.3...357180.367192.0.367416.32.27.2.3.0.1.190.2659.20j7.27.0....0...1ac.1j4.34.heirloom-serp..7.25.2182.-fzuj7TGmno
	*/
	if(Settings.Referrer.DenySequences.Action == Action::Disabled)
		Settings.Referrer.DenySequences.Action = Action::Block;

	AddNotInList(Settings.URL.DenySequences.List,"data:"); //url(data:test/html;base64,
	AddNotInList(Settings.Cookie.DenySequences.List,"data:");
	AddNotInList(Settings.Referrer.DenySequences.List,"data:");
	AddNotInList(Settings.QueryString.DenySequences.List,"data:");
	AddNotInList(Settings.Post.DenySequences.List,"data:");

	AddNotInList(Settings.URL.DenySequences.List,"base64");
	AddNotInList(Settings.Referrer.DenySequences.List,"base64");
	AddNotInList(Settings.Cookie.DenySequences.List,"base64");
	AddNotInList(Settings.QueryString.DenySequences.List,"base64");
	AddNotInList(Settings.Post.DenySequences.List,"base64");

	AddNotInList(Settings.URL.DenySequences.List,"charset=");
	//AddNotInList(Settings.Referrer.DenySequences.List,"charset="); //allow in referrer
	AddNotInList(Settings.Cookie.DenySequences.List,"charset=");
	AddNotInList(Settings.QueryString.DenySequences.List,"charset=");
	AddNotInList(Settings.Post.DenySequences.List,"charset=");

	AddNotInList(Settings.URL.DenySequences.List,"mhtml:");
	AddNotInList(Settings.Referrer.DenySequences.List,"mhtml:");
	AddNotInList(Settings.Cookie.DenySequences.List,"mhtml:");
	AddNotInList(Settings.QueryString.DenySequences.List,"mhtml:");
	AddNotInList(Settings.Post.DenySequences.List,"mhtml:");

	AddNotInList(Settings.Filename.Deny.List,"soapcaller.bs");
	AddNotInList(Settings.Filename.Deny.List,".sql.");
	AddNotInList(Settings.Filename.Deny.List,"testproxy.");
	AddNotInList(Settings.Filename.Deny.List,"psexec");

	AddNotInList(Settings.Extensions.Deny.List,".accdb");
	AddNotInList(Settings.Extensions.Deny.List,".php-");
	AddNotInList(Settings.Extensions.Deny.List,".php-s");

	if(!Settings.WebApp.Allow_PHP) //don't add for existing upgrades when PHP enabled
		AddNotInList(Settings.QueryString.DenySequences.List,".php");

	//block command line download tools
	Settings.AddAllRegex("Command curl http",CSignatures::RegexPatternCommandLine("curl","http")); //curl -o http
	Settings.AddAllRegex("Command fetch http",CSignatures::RegexPatternCommandLine("fetch","http"));
	Settings.AddAllRegex("Command lwp-download http",CSignatures::RegexPatternCommandLine("lwp-download","http"));
	Settings.AddAllRegex("Command wget http",CSignatures::RegexPatternCommandLine("wget","http"));
	Settings.AddAllRegex("Command ping",CSignatures::RegexPatternCommandLine("ping","((\\d(\\d)?(\\d)?[.]\\d(\\d)?(\\d)?[.]\\d(\\d)?(\\d)?[.]\\d(\\d)?(\\d)?)|((\\h)*:(\\h)*:(\\h)*)|(localhost)|((\\a)+[.]\\a(\\a)+))"));

	//block C-style browser bugs:
	Settings.AddAllList("\\o00");
	Settings.AddAllList("\\x00"); //<scr\x00ipt>confirm(1);</scr\x00ipt>
	Settings.AddAllList("\\u0000");
	Settings.AddAllRegex("Browser Unicode ASCII Obfuscation","\\\\u00\\h\\h"); //ascii in unicode

	//block archive files (zip/rar/tar/tar.gz/gz/7z/tgz) in website root (tool is also blocked as hacktool in 4.3 "python-requests" + multiple client errors)
	if(Settings.URL.DenyRegex.Action==Action::Disabled)
		Settings.URL.DenyRegex.Action = Action::Block;
	Settings.AddNotInMap(Settings.URL.DenyRegex.Map,"Archive files in root","^(http(s)?:(/)+([^/])+)?/(/)*([^/])*[.]((u?zip)|(r|tar)|(t?gz)|(7z))");

	//Deny Host header IP (worm propagation)
	Settings.AddNotInMap(Settings.Headers.DenyRegex.Map,"Host Header IPv4 (Worm propagation)",CSignatures::RegexPatternHttpHeader("host","\\d\\d?\\d?\\.\\d\\d?\\d?\\.\\d\\d?\\d?\\.\\d\\d?\\d?"));
	Settings.AddNotInMap(Settings.Headers.DenyRegex.Map,"Host Header IPv6 (Worm propagation)",CSignatures::RegexPatternHttpHeader("host","[\\[]"));
	//HEADERS - typo's
	Settings.Headers.DenyHeaders.List.AddTail("Accpet:");
	Settings.Headers.DenyHeaders.List.AddTail("UserAgent:");
	Settings.Headers.DenyHeaders.List.AddTail("X-Fowarded-For:");

	//ASP Request Object (doesn't return server variable when it is present in cookie/query/form/clientcertificate)
	//https://msdn.microsoft.com/en-us/library/ms524948%28v=vs.90%29.aspx
	Settings.AddAllPayloads("appl_physical_path=");
	Settings.AddAllPayloads("auth_type=");
	Settings.AddAllPayloads("auth_user=");
	Settings.AddAllPayloads("instance_id=");
	Settings.AddAllPayloads("instance_meta_path=");
	Settings.AddAllPayloads("local_addr=");
	Settings.AddAllPayloads("logon_user=");
	Settings.AddAllPayloads("path_info=");
	Settings.AddAllPayloads("path_translated=");
	Settings.AddAllPayloads("query_string=");
	Settings.AddAllPayloads("remote_addr=");
	Settings.AddAllPayloads("remote_host=");
	Settings.AddAllPayloads("request_method=");
	Settings.AddAllPayloads("script_name=");
	Settings.AddAllPayloads("server_name=");
	Settings.AddAllPayloads("http_host=");
	Settings.AddAllPayloads("http_referer=");
	Settings.AddAllPayloads("http_cookie=");

	//seen in webshells
	Settings.AddAllRegex("ASP Directive","<%@.+?%>");
	Settings.AddAllRegex("ASP Page","<%@" + CSignatures::RegexPatternHtmlWhitespace() + "page");
	Settings.AddAllList("filesystemobject");
	Settings.AddAllList("processstartinfo");
	Settings.AddAllList("frombase64string");
	Settings.AddAllList("$_get");
	Settings.AddAllList("$_post");
	Settings.AddAllList("$_cookies");
}

void CWebKnightUpgrade::Upgrade4_5(CWebKnightSettings& Settings)
{
	Settings.AddAllList("$_request");
	Settings.AddAllList("$http_cookie_vars");
	Settings.AddAllList("$http_get_vars");
	Settings.AddAllList("$http_post_vars");
	Settings.AddAllList("&colon;"); //data&colon;text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
	
	AddNotInList(Settings.Extensions.Deny.List,".php_backup");
	AddNotInList(Settings.Extensions.Deny.List,".suspected_");
	AddNotInList(Settings.Extensions.Deny.List,".xsql");

	//extensions blocked by IIS HttpForbiddenHandler (but .NET version information disclosure on page)
	AddNotInList(Settings.Extensions.Deny.List,".aspq");
	AddNotInList(Settings.Extensions.Deny.List,".cshtm");
	AddNotInList(Settings.Extensions.Deny.List,".cshtml");
	AddNotInList(Settings.Extensions.Deny.List,".vbhtm");
	AddNotInList(Settings.Extensions.Deny.List,".vbhtml");

	//HEADERS - typo's and other mistakes
	Settings.Headers.DenyHeaders.List.AddTail("Accepts:");
	//Settings.Headers.DenyHeaders.List.AddTail("Acbept-Encoding:");
	//Settings.Headers.DenyHeaders.List.AddTail("Accdpt-Encoding:");
	Settings.Headers.DenyHeaders.List.AddTail("Accept_Charset:");
	Settings.Headers.DenyHeaders.List.AddTail("Accept_Language:");
	//Settings.Headers.DenyHeaders.List.AddTail("Bccept-Encoding:");
	Settings.Headers.DenyHeaders.List.AddTail("Content-Suport:");
	Settings.Headers.DenyHeaders.List.AddTail("HTTP_X_FORWARDED_FOR:");
	Settings.Headers.DenyHeaders.List.AddTail("Refer:");
	Settings.Headers.DenyHeaders.List.AddTail("Referrer:");
	Settings.Headers.DenyHeaders.List.AddTail("REMOTE-ADDR:");
	Settings.Headers.DenyHeaders.List.AddTail("REMOTE_ADDR:");
	Settings.Headers.DenyHeaders.List.AddTail("REMOTE-HOST:");
	Settings.Headers.DenyHeaders.List.AddTail("REMOTE_HOST:");
	Settings.Headers.DenyHeaders.List.AddTail("X-Forwarded_For:");
}

void CWebKnightUpgrade::Upgrade4_6(CWebKnightSettings& Settings)
{
	AddNotInList(Settings.Headers.DenySequences.List,"en;q=0.5\"accept-encoding:\"gzip");
	AddNotInList(Settings.Headers.DenySequences.List,"name: user-agent"); //Connection: Keep-Alive  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8  Accept-Encoding: gzip, deflate  Accept-Language: en,*  Host: *******.com  User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) splash Safari/538.1  name: User-Agent  value: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox38.0
	AddNotInList(Settings.Headers.DenySequences.List,"nopnopnopjmp0x9mb"); //nopwd: NOPNOPNOPJMP0x9mb
	AddNotInList(Settings.Headers.DenySequences.List,"seckey: fuckpassport"); //SecKey: FuckPassport
	AddNotInList(Settings.Headers.DenySequences.List,"() {"); //Block obvious ShellShock attacks (can by bypassed, add regex below if you need to detect all of them)
	//AddNotInMap(Settings.Headers.DenyRegex.Map,"ShellShock","\\(\\)(\\b|\\n|[\\f\\v])*\\{"); //has a small performance impact + not an attack on IIS
	AddNotInList(Settings.Headers.DenySequences.List,"id: mozilla/4.0 (compatible; msie 6.0; windows nt 5.2; .net clr 1.0.3705;)");

	Settings.Headers.DenyHeaders.List.AddTail("charset:");
	Settings.Headers.DenyHeaders.List.AddTail("contentType:");
	Settings.Headers.DenyHeaders.List.AddTail("Content-types:");
	Settings.Headers.DenyHeaders.List.AddTail("Gyoarazujo:");
	Settings.Headers.DenyHeaders.List.AddTail("HTTP_DNS:");
	Settings.Headers.DenyHeaders.List.AddTail("HTTPS:");
	Settings.Headers.DenyHeaders.List.AddTail("use-agent:");
	Settings.Headers.DenyHeaders.List.AddTail("USER_AGENT:");
	Settings.Headers.DenyHeaders.List.AddTail("'User-Agent':");
	Settings.Headers.DenyHeaders.List.AddTail("Vuln:");
	Settings.Headers.DenyHeaders.List.AddTail("X-Detectify:");
	Settings.Headers.DenyHeaders.List.AddTail("X_FORWARDED_FOR:");	
	Settings.Headers.DenyHeaders.List.AddTail("x-forwarder-for:");
	Settings.Headers.DenyHeaders.List.AddTail("X-Forward-For:");
	Settings.Headers.DenyHeaders.List.AddTail("X-Bogus:");
	Settings.Headers.DenyHeaders.List.AddTail("0:");

	AddNotInList(Settings.Filename.Deny.List,"composer.lock");
	AddNotInList(Settings.Filename.Deny.List,".php~.");
	AddNotInList(Settings.Extensions.Deny.List,".lock");
	AddNotInList(Settings.Extensions.Deny.List,".lnk");
	AddNotInList(Settings.Extensions.Deny.List,".cgi");
	AddNotInList(Settings.Extensions.Deny.List,".orig");

	//certificate extensions
	//http://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file
	AddNotInList(Settings.Extensions.Deny.List,".cer");
	AddNotInList(Settings.Extensions.Deny.List,".cert");
	AddNotInList(Settings.Extensions.Deny.List,".crt");
	AddNotInList(Settings.Extensions.Deny.List,".der");
	AddNotInList(Settings.Extensions.Deny.List,".key");
	AddNotInList(Settings.Extensions.Deny.List,".pem");
	AddNotInList(Settings.Extensions.Deny.List,".pkcs12");
	AddNotInList(Settings.Extensions.Deny.List,".pfx");
	AddNotInList(Settings.Extensions.Deny.List,".p12");

	//awk injection
	AddNotInList(Settings.Filename.Deny.List,"cmd.php");
	AddNotInList(Settings.Filename.Deny.List,"command.php");
	Settings.AddAllList("awk 'begin"); //cmd=awk%20%27BEGIN%7bs%3d%22/inet/tcp/21614/0/0%22%3bfor%28%3bs%7c%26getline%20c%3bclose%28c%29%29while%28c%7cgetline%29print%7c%26s%3bclose%28s%29%7d%27
	Settings.AddAllList("/inet/tcp");
	Settings.AddAllList("/inet/udp");

	//block perl reverse shells and other perl injections
	//http://bernardodamele.blogspot.be/2011/09/reverse-shells-one-liners.html
	//cid=3&name=h5VHz7dQA1";perl -MIO -e '$p=fork();exit,if$p;foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(LocalPort,7953,Reuse,1,Listen)->accept;$~->fdopen($c,w);STDIN->fdopen($c,r);while(<>){if($_=~ /(.*)/){system $1;}};';&email=fKxQLiglCt&subject=F9KAxrlsmD&message=ogjheY3HpC&action=Send&mailinglist=0&cc=0
	//pdf=make&pfilez=xxx%3b%20perl%20-MIO%20-e%20%27%24p%3dfork%28%29%3bexit%2cif%24p%3bforeach%20my%20%24key%28keys%20%25ENV%29%7bif%28%24ENV%7b%24key%7d%3d~/%28.%2a%29/%29%7b%24ENV%7b%24key%7d%3d%241%3b%7d%7d%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28LocalPort%2c16776%2cReuse%2c1%2cListen%29-%3eaccept%3b%24~-%3efdopen%28%24c%2cw%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3bwhile%28%3c%3e%29%7bif%28%24_%3d~%20/%28.%2a%29/%29%7bsystem%20%241%3b%7d%7d%3b%27
	//Settings.AddAllRegex("Perl reverse shell","perl\\b+-mio"); //perl -MIO (small performance impact + not an attack on IIS)
	Settings.AddAllList("perl -mio");//perl -MIO (can be bypassed, add regex above if you need to detect all of them)
	Settings.AddAllList("io::socket::");
	AddNotInList(Settings.URL.DenySequences.List,"/cgi-perl");
	AddNotInList(Settings.URL.DenySequences.List,"/gitweb.perl");
	AddNotInList(Settings.URL.DenySequences.List,"/perl");
	AddNotInList(Settings.URL.DenySequences.List,"/perl/");
	AddNotInList(Settings.URL.DenySequences.List,"/perl/-e");
	AddNotInList(Settings.URL.DenySequences.List,"/perl5/");
	AddNotInList(Settings.URL.DenySequences.List,"/perl-status");
	Settings.AddAllList("/bin/sh");
	Settings.AddAllList("ruby -rsocket");//ruby -rsocket (can by bypassed, add regex below if you need to detect all of them)
	//Settings.AddAllRegex("Ruby reverse shell","ruby\\b+-rsocket"); //ruby -rsocket (small performance impact + not an attack on IIS)

	//block ¼script (https://html5sec.org/#19)
	Settings.AddAllList("¼script"); //needed change in XML declaration (encoding)

	AddNotInList(Settings.Post.DenySequences.List,"!ruby/hash"); //YAML exploit: https://www.sitepoint.com/anatomy-of-an-exploit-an-in-depth-look-at-the-rails-yaml-vulnerability/
}

void CWebKnightUpgrade::Upgrade4_7(CWebKnightSettings& Settings)
{
	AddNotInList(Settings.Headers.DenySequences.List,"name: user-agent");
	AddNotInList(Settings.Headers.DenySequences.List,"if-modified-since: 0");
	//AddNotInList(Settings.Headers.DenySequences.List,"");
	//AddNotInList(Settings.Headers.DenySequences.List,"");
	//AddNotInList(Settings.Headers.DenySequences.List,"");

	Settings.Headers.DenyHeaders.List.AddTail("KeepAlive:");
	Settings.Headers.DenyHeaders.List.AddTail("Upgrade-Insecures-Request:");
	Settings.Headers.DenyHeaders.List.AddTail("WWW-Authenticate:");
	Settings.Headers.DenyHeaders.List.AddTail("X_FORWARD_FOR:");
	Settings.Headers.DenyHeaders.List.AddTail("REMOTE_USER:"); //REMOTE_USER: hydra.admin
	Settings.Headers.DenyHeaders.List.AddTail("X-Forwarded:");
	Settings.Headers.DenyHeaders.List.AddTail("Pragma-directive:");
	Settings.Headers.DenyHeaders.List.AddTail("Cache-directive:");

	Settings.AddAllList("<data");
	Settings.AddAllList("createobject");
	Settings.AddAllList("wscript.shell");
	Settings.AddAllList("response.write");

	AddNotInList(Settings.URL.DenySequences.List,"/.ftpconfig");
	AddNotInList(Settings.URL.DenySequences.List,"/.remote-sync.json");
	AddNotInList(Settings.URL.DenySequences.List,"/.vscode");
	AddNotInList(Settings.URL.DenySequences.List,"/sftp-config.json");
	AddNotInList(Settings.URL.DenySequences.List,"/deployment-config.json");
	AddNotInList(Settings.URL.DenySequences.List,"/.lib");
	AddNotInList(Settings.URL.DenySequences.List,"/.list");
	AddNotInList(Settings.URL.DenySequences.List,"/.ssh/id_dsa");
	AddNotInList(Settings.URL.DenySequences.List,"/.ssh/id_rsa");
	AddNotInList(Settings.URL.DenySequences.List,"/.env");
	AddNotInList(Settings.URL.DenySequences.List,"/.cvsignore");
	AddNotInList(Settings.URL.DenySequences.List,"/.project");
	AddNotInList(Settings.URL.DenySequences.List,"/.bitcoin/wallet.dat");
	AddNotInList(Settings.URL.DenySequences.List,"/bitcoin_wallet.dat.1");

	AddNotInList(Settings.Filename.Deny.List,"90sec.php");	//remote shell
	AddNotInList(Settings.Filename.Deny.List,"90000.php");	//remote shell

	//https://neonprimetime.blogspot.be/2015/11/more-php-injection-obfuscation.html
	Settings.AddAllList("@eval");

	//https://www.exploit-db.com/exploits/17644/
	Settings.AddAllList("<filesmatch");

	//obfuscated struts exploit
	/*
		debug=command&expression=#req=#context.get('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletReq'+'uest'),#resp=#context.get
		('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletRes'+'ponse'),#resp.setCharacterEncoding('UTF-8'),#resp.getWriter().print
		("security_"),#resp.getWriter().print("check"),#resp.getWriter().flush(),#resp.getWriter().close()
		ALLOWEDblock #context.get
	*/
	Settings.AddAllList("#context.get");

	/*
		1=%40ini_set%28%22display_errors%22%2C%220%22%29%3B%40set_time_limit%280%29%3B%40set_magic_quotes_runtime%280%29%
		3Becho%20%27-%3E%7C%27%3Bfile_put_contents%28%24_SERVER%5B%27DOCUMENT_ROOT%27%5D.%27/webconfig.txt.php%27%
		2Cbase64_decode%28%27PD9waHAgZXZhbCgkX1BPU1RbMV0pOz8%2B%27%29%29%3Becho%20%27%7C%3C-%27%3B
	*/
	Settings.AddAllList("ini_set(");
	Settings.AddAllList("file_put_contents(");
	Settings.AddAllList("file_get_contents(");

	//TODO: 4.7 - test if new webknight.xml is longer than 32768 pixels
}