/*
    AQTRONIX C++ Library
    Copyright 2015 Parcifal Aertssen

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
#include "Signatures.h"
#include "StringHelper.h"

CSignatures::CSignatures(void)
{
}

CSignatures::~CSignatures(void)
{
}

void CSignatures::JavaScript(CStringList& list)
{
	list.AddTail("javascript:");
	list.AddTail("behavior:");
	list.AddTail("animationend");		//added 2015
	list.AddTail("animationiteration");	//added 2015
	list.AddTail("animationstart");		//added 2015
	list.AddTail("onabort");
	list.AddTail("onactivate");			//added 2011
	list.AddTail("onafterprint");		//added 2011
	list.AddTail("onafterupdate");		//added 2011
	list.AddTail("onautocomplete");		//added 2015 Reported by Ashar Javed
	list.AddTail("onautocompleteerror");//added 2015 Reported by Ashar Javed
	list.AddTail("onbeforeactivate");	//added 2011
	list.AddTail("onbeforecopy");		//added 2011
	list.AddTail("onbeforecut");		//added 2011
	list.AddTail("onbeforepaste");		//added 2011
	list.AddTail("onbeforedeactivate");	//added 2011
	list.AddTail("onbeforeeditfocus");	//added 2011
	list.AddTail("onbeforeprint");		//added 2011
	list.AddTail("onbeforeunload");		//added 2011/Fixed 2013 o->u
	list.AddTail("onbeforeupdate");		//added 2011
	list.AddTail("onbegin");			//added 2015
	list.AddTail("onblur");
	list.AddTail("onbounce");			//added 2013 (marquee) Reported by Rafay Baloch
	list.AddTail("oncancel");			//added 2015 Reported by Ashar Javed
	list.AddTail("oncanplay");			//added 2011
	list.AddTail("oncanplaythrough");	//added 2011
	list.AddTail("oncellchange");		//added 2011
	list.AddTail("onchange");
	list.AddTail("onclick");
	list.AddTail("onclose");			//added 2015 Reported by Ashar Javed
	list.AddTail("oncontextmenu");		//added 2011
	list.AddTail("oncontrolselect");	//added 2011
	list.AddTail("oncopy");				//added 2011
	list.AddTail("oncuechange");		//added 2015 Reported by Ashar Javed
	list.AddTail("oncut");				//added 2011
	list.AddTail("ondataavailable");	//added 2011
	list.AddTail("ondatasetchanged");	//added 2011
	list.AddTail("ondatasetcomplete");	//added 2011
	list.AddTail("ondblclick");
	list.AddTail("ondeactivate");		//added 2011
	list.AddTail("ondevicelight");		//added 2015
	list.AddTail("ondevicemotion");		//added 2015
	list.AddTail("ondeviceorientation");//added 2015
	list.AddTail("ondeviceproximity");	//added 2015
	list.AddTail("ondragdrop");
	list.AddTail("ondrag");				//added 2011
	list.AddTail("ondragend");			//added 2011
	list.AddTail("ondragenter");		//added 2011
	list.AddTail("ondragexit");			//added 2015 Reported by Ashar Javed
	list.AddTail("ondragleave");		//added 2011
	list.AddTail("ondragover");			//added 2011
	list.AddTail("ondragstart");		//added 2011
	list.AddTail("ondrop");				//added 2011
	list.AddTail("ondurationchange");	//added 2011
	list.AddTail("onemptied");			//added 2011
	list.AddTail("onend");
	list.AddTail("onended");			//added 2011
	list.AddTail("onerror");
	list.AddTail("onerrorupdate");		//added 2011
	list.AddTail("onfilterchange");		//added 2011
	list.AddTail("onfinish");			//added 2013 (marquee) Reported by Rafay Baloch
	list.AddTail("onfocus");
	list.AddTail("onfocusin");			//added 2011
	list.AddTail("onfocusout");			//added 2011
	list.AddTail("onformchange");		//added 2011
	list.AddTail("onforminput");		//added 2011
	list.AddTail("onhaschange");		//added 2011
	list.AddTail("onhashchange");		//added 2013 http://help.dottoro.com/larrqqck.php
	list.AddTail("onhelp");				//added 2011
	list.AddTail("oninput");			//added 2011
	list.AddTail("oninvalid");			//added 2011
	list.AddTail("onkeydown");
	list.AddTail("onkeypress");
	list.AddTail("onkeyup");
	list.AddTail("onlanguagechange");	//added 2015
	list.AddTail("onlayoutcomplete");	//added 2011                                    
	list.AddTail("onload");
	list.AddTail("onloadeddata");		//added 2011
	list.AddTail("onloadedmetadata");	//added 2011
	list.AddTail("onloadstart");		//added 2011 (fixed 2015)
	list.AddTail("onlosecapture");		//added 2011
	list.AddTail("onmediacomplete");	//added 2015
	list.AddTail("onmediaerror");		//added 2015
	list.AddTail("onmessage");			//added 2011
	list.AddTail("onmousedown");
	list.AddTail("onmouseenter");		//added 2011
	list.AddTail("onmouseleave");		//added 2011
	list.AddTail("onmousemove");		//added 2011
	list.AddTail("onmouseout");
	list.AddTail("onmouseover");
	list.AddTail("onmouseup");
	list.AddTail("onmousewheel");		//added 2011
	list.AddTail("onmove");
	list.AddTail("onmoveend");			//added 2011
	list.AddTail("onmovestart");		//added 2011
	list.AddTail("onoffline");			//added 2011
	list.AddTail("ononline");			//added 2011
	list.AddTail("onoutofsync");		//added 2015
	list.AddTail("onopen");				//added 2015
	list.AddTail("onpagehide");			//added 2011
	list.AddTail("onpageshow");			//added 2011
	list.AddTail("onpaste");			//added 2011
	list.AddTail("onpause");			//added 2011
	list.AddTail("onplay");				//added 2011
	list.AddTail("onplaying");			//added 2011
	list.AddTail("onpopstate");			//added 2011
	list.AddTail("onprogress");			//added 2011
	list.AddTail("onpropertychange");	//added 2011
	list.AddTail("onratechange");		//added 2011
	list.AddTail("onreadystatechange");	//added 2011
	list.AddTail("onredo");				//added 2011
	list.AddTail("onrepeat");			//added 2015
	list.AddTail("onreset");
	list.AddTail("onresize");
	list.AddTail("onresizeend");		//added 2011
	list.AddTail("onresizestart");		//added 2011
	list.AddTail("onresume");			//added 2015
	list.AddTail("onreverse");			//added 2015
	list.AddTail("onrowenter");			//added 2011
	list.AddTail("onrowexit");			//added 2011
	list.AddTail("onrowsdelete");		//added 2011
	list.AddTail("onrowsinserted");		//added 2011
	list.AddTail("onscroll");			//added 2011
	list.AddTail("onsearch");			//added 2013 http://help.dottoro.com/larrqqck.php
	list.AddTail("onseek");				//added 2015
	list.AddTail("onseeked");			//added 2011
	list.AddTail("onseeking");			//added 2011
	list.AddTail("onselect");
	list.AddTail("onselectionchange");	//added 2013 http://help.dottoro.com/larrqqck.php
	list.AddTail("onselectstart");		//added 2011
	list.AddTail("onshow");				//added 2015 Reported by Mazin Ahmed
	list.AddTail("onsort");				//added 2015 Reported by Ashar Javed
	list.AddTail("onstalled");			//added 2011
	list.AddTail("onstart");			//added 2013 (marquee) Reported by Rafay Baloch
	list.AddTail("onstop");				//added 2013 http://help.dottoro.com/larrqqck.php
	list.AddTail("onstorage");			//added 2011
	list.AddTail("onsubmit");
	list.AddTail("onsuspend");			//added 2011
	list.AddTail("onsyncrestored");		//added 2015
	list.AddTail("ontimeerror");		//added 2011
	list.AddTail("ontimeupdate");		//added 2011
	list.AddTail("ontouchcancel");		//added 2015
	list.AddTail("ontouchend");			//added 2015
	list.AddTail("ontouchmove");		//added 2015
	list.AddTail("ontouchstart");		//added 2015
	list.AddTail("ontoggle");			//added 2015 Reported by Mazin Ahmed
	list.AddTail("ontrackchange");		//added 2015
	list.AddTail("onundo");				//added 2011
	list.AddTail("onunload");
	list.AddTail("onurlflip");			//added 2015
	list.AddTail("onuserproximity");	//added 2015
	list.AddTail("onvolumechange");		//added 2011
	list.AddTail("onwheel");			//added 2015
	list.AddTail("onwaiting");			//added 2011
	list.AddTail("seeksegmenttime");	//added 2015
	list.AddTail("transitionend");		//added 2015
	list.AddTail("style=");				//added 2011
	list.AddTail("<isindex");			//added 2013 (isindex) Reported by Rafay Baloch
	list.AddTail("formaction");			//added 2013 (isindex) Reported by Rafay Baloch
	//see: http://boho.or.kr/upload/file/EpF447.pdf
	list.AddTail("&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a"); //html-encode "javascript:"
	list.AddTail("expression(");

	list.AddTail("domattrmodified");
	list.AddTail("domcharacterdatamodified");
	list.AddTail("domfocusin");
	list.AddTail("domfocusout");
	list.AddTail("dommousescroll");
	list.AddTail("domnodeinserted");
	list.AddTail("domnodeinsertedintodocument");
	list.AddTail("domnoderemoved");
	list.AddTail("domnoderemovedfromdocument");
	list.AddTail("domsubtreemodified");

	list.AddTail("fromcharcode");

	//Howest Honeypot Project 2015
	list.AddTail("onfullscreenchange");
	list.AddTail("onsvgload");
	list.AddTail("onsvgunload");
	list.AddTail("onvisibilitychange");
}

void CSignatures::VBScript(CStringList& list)
{
	list.AddTail("activexobject");
	list.AddTail("vbscript:");
}

void CSignatures::SQLInjection(CStringList& List)
{
	//SQL Injection (words in list should be lowercase, if 2 or more are found, request will be blocked)
	//used resources: next generation security software documents, Snort rules
	List.RemoveAll();
	List.AddTail("'");	//don't allow escaping string
	List.AddTail("`");	//MySQL string escape character
	//List.AddTail("\"");	//can be used in MySQL and in SQL Server when you set QUOTED_IDENTIFIER OFF (default ON) //but also needed in XML and HTML
	List.AddTail(";");	//don't allow escaping numeric value
	List.AddTail("--");	//don't allow commenting
	List.AddTail("/*");	//don't allow commenting
	List.AddTail("*/");	//don't allow commenting
	List.AddTail("/*!");	//SQLMap modsecurityversioned.py
	List.AddTail("/*!0");	//SQLMap halfversionedmorekeywords.py
	List.AddTail("select ");
	List.AddTail("select(");
	List.AddTail("insert ");
	List.AddTail("insert(");
	List.AddTail("update ");
	List.AddTail("update(");
	List.AddTail("delete ");
	List.AddTail("delete(");
	List.AddTail("drop ");
	List.AddTail("drop(");
	List.AddTail("alter ");	//false positive: "aalter"
	List.AddTail("alter(");	//false positive: "aalter"
	List.AddTail("create ");
	List.AddTail("create(");
	List.AddTail("backup ");
	List.AddTail("backup(");
	List.AddTail("inner join");
	List.AddTail("from ");
	List.AddTail("from(");
	List.AddTail("where ");
	List.AddTail("where(");
	List.AddTail("group by");
	List.AddTail("having ");
	List.AddTail("having(");
	List.AddTail("order by");
	List.AddTail("union ");
	List.AddTail("union(");
	List.AddTail("intersect ");
	List.AddTail("intersect(");
	List.AddTail("except ");
	List.AddTail("except(");
	List.AddTail("case when");
	List.AddTail("exists ");
	List.AddTail("exists(");
	List.AddTail(" table ");//keyword "executable " blocked for sqli
	List.AddTail("not in(");
	List.AddTail(" in(");

	List.AddTail("shutdown");
	List.AddTail("kill ");
	List.AddTail("declare");
	List.AddTail("openrowset");
	List.AddTail("opendatasource");
	List.AddTail("pwdencrypt");
	List.AddTail("msdasql");
	List.AddTail("sqloledb");

	List.AddTail("quotename");
	List.AddTail("isnull");
	List.AddTail("xtype");
	List.AddTail("varchar");
	List.AddTail("cast(");
	List.AddTail("chr(");
	List.AddTail("char(");
	List.AddTail("char(124)");
	List.AddTail("char(9)");
	List.AddTail("char(94)");
	List.AddTail("char(32)");
	List.AddTail("char(85)");
	List.AddTail("char(60)"); //stored XSS <;
	List.AddTail("char(62)"); //stored XSS >;
	List.AddTail("charindex(");
	List.AddTail("concat(");
	List.AddTail("concat_ws("); //SQLMap concat2concatws.py
	List.AddTail("convert(");
	List.AddTail("substring(");
	List.AddTail("substr(");
	List.AddTail("left(");
	List.AddTail("mid(");
	List.AddTail("right(");
	List.AddTail("length(");
	List.AddTail("locate(");
	List.AddTail("instr(");
	List.AddTail("textpos(");

	List.AddTail("all(");
	List.AddTail("any(");
	List.AddTail("some(");
	//aggregate functions
	List.AddTail("avg(");
	List.AddTail("count(");
	List.AddTail("max(");
	List.AddTail("min(");
	List.AddTail("sum(");

	List.AddTail("cursor");
	List.AddTail("fetch next");
	List.AddTail("allocate");	//also deallocate

	List.AddTail("raiserror");
	//List.AddTail("execute");  //detected by "exec"
	List.AddTail("exec");
	List.AddTail("=!(");

	List.AddTail("dbo.");
	List.AddTail("master..");
	List.AddTail("tempdb..");
	List.AddTail("@@version");
	List.AddTail("@@servername");
	List.AddTail("@@servicename");
	List.AddTail("@@fetch_status");

	List.AddTail("syslogins");
	List.AddTail("sysxlogins");
	List.AddTail("sysdatabases");
	List.AddTail("sysobjects");
	List.AddTail("syscomments");
	List.AddTail("syscolumns");
	List.AddTail("sysname");
	List.AddTail("systypes");
	List.AddTail("system_user");

	List.AddTail("db_name");
	List.AddTail("db_id");
	List.AddTail("information_schema");
	List.AddTail("is_member");
	List.AddTail("is_srvrolemember");
	List.AddTail("object_id");
	List.AddTail("object_name");
	List.AddTail("col_length");
	List.AddTail("col_name");
	List.AddTail("column_name");
	List.AddTail("table_name");

	List.AddTail("0x31303235343830303536"); //Havij injection

	//see e-mail of Frank Block
	List.AddTail("' or '");
	List.AddTail("'or '");
	List.AddTail("'or'");
	List.AddTail("' or'");
	List.AddTail("\" or \"");
	List.AddTail("\"or \"");
	List.AddTail("\"or\"");
	List.AddTail("\" or\"");
	List.AddTail("or 1 --");
	List.AddTail("or 1--");
	List.AddTail("or 1=");

	List.AddTail("' and '");
	List.AddTail("'and '");
	List.AddTail("'and'");
	List.AddTail("' and'");
	List.AddTail("\" and \"");
	List.AddTail("\"and \"");
	List.AddTail("\"and\"");
	List.AddTail("\" and\"");
	List.AddTail("and 1 --");
	List.AddTail("and 1--");
	List.AddTail("and 1=");
	List.AddTail("' xor '");
	List.AddTail("'xor '");
	List.AddTail("'xor'");
	List.AddTail("' xor'");
	List.AddTail("\" xor \"");
	List.AddTail("\"xor \"");
	List.AddTail("\"xor\"");
	List.AddTail("\" xor\"");
	List.AddTail("xor 1 --");
	List.AddTail("xor 1--");
	List.AddTail("xor 1=");
	List.AddTail("' like '"); //Thanks Joe McCray
	List.AddTail("'like '");
	List.AddTail("'like'");
	List.AddTail("' like'");
	List.AddTail("\" like \"");
	List.AddTail("\"like \"");
	List.AddTail("\"like\"");
	List.AddTail("\" like\"");
	List.AddTail("1 like 1");
	List.AddTail("' between '");
	List.AddTail("'between '");
	List.AddTail("'between'");
	List.AddTail("' between'");
	List.AddTail("\" between \"");
	List.AddTail("\"between \"");
	List.AddTail("\"between\"");
	List.AddTail("\" between\"");
	List.AddTail("1 between 1 and 1");

	//See mail of Khalil Bijjou
	List.AddTail("'='");
	List.AddTail("'<'");
	List.AddTail("'>'");
	List.AddTail("'<>'");
	List.AddTail("'!='");
	List.AddTail("'<='");
	List.AddTail("'>='");
	List.AddTail("'!<'");
	List.AddTail("'!>'");
	List.AddTail("'+'");
	List.AddTail("'&'"); //Howest Honeypot Project 2015
	List.AddTail("'<=>'");
	List.AddTail("1'='1");
	List.AddTail("\"=\"");
	List.AddTail("\"<\"");
	List.AddTail("\">\"");
	List.AddTail("\"<>\"");
	List.AddTail("\"!=\"");
	List.AddTail("\"<=\"");
	List.AddTail("\">=\"");
	List.AddTail("\"!<\"");
	List.AddTail("\"!>\"");
	List.AddTail("\"+\"");
	List.AddTail("\"<=>\"");
	List.AddTail("1\"=\"1");
	//List.AddTail("1=1"); //dangerous to block this
	List.AddTail("1<1");
	List.AddTail("1>1");
	List.AddTail("1<>1");
	List.AddTail("1!=1");
	List.AddTail("1<=1");
	List.AddTail("1>=1");
	List.AddTail("1!<1");
	List.AddTail("1!>1");
	List.AddTail("1<=>1");
	/*
		Web Application Firewalls
		Evaluation and Analysis
		Andreas Karakannas
		George Thessalonikefs
	*/
	List.AddTail("||");
	List.AddTail("&&");

	List.AddTail("'a=0");
	List.AddTail("'0=a");
	List.AddTail("'0x");
	List.AddTail("'sql");
	List.AddTail("[sqlinjection]");
	List.AddTail("[sql injection]");
	List.AddTail("[sqli]");
	List.AddTail("id='");
	List.AddTail("'0having'");				//SQLMap securesphere.py
	List.AddTail("'0having'='0having'");	//SQLMap securesphere.py
	List.AddTail("WCRTESTINPUT");

	List.AddTail("benchmark(");
	List.AddTail("database()");
	List.AddTail("schema()");
	List.AddTail("dbms_pipe.receive_message");
	List.AddTail("ascii(");
	List.AddTail("bin(");
	List.AddTail("hex(");
	List.AddTail("ord(");
	List.AddTail("load_file(");
	List.AddTail("load data infile");
	List.AddTail("utf_file(");
	List.AddTail("name_const(");
	List.AddTail("getdate(");
	List.AddTail("sysdate(");
	List.AddTail("now()");
	List.AddTail("user()");
	List.AddTail("version()");
	List.AddTail("sleep(");
	List.AddTail("pg_sleep(");
	List.AddTail("waitfor");
	List.AddTail("waitfor delay");
	List.AddTail("@@datadir");
	List.AddTail("@@hostname");

	//https://dev.mysql.com/doc/refman/5.7/en/control-flow-functions.html
	List.AddTail("if(");
	List.AddTail("ifnull(");
	List.AddTail("nullif(");

	//https://dev.mysql.com/doc/refman/5.7/en/comparison-operators.html
	List.AddTail("coalesce(");
	List.AddTail("greatest(");	//SQLMap greatest.py
	List.AddTail("interval(");
	List.AddTail("is null");
	//List.AddTail("is not");	//false positives
	List.AddTail("is not null");
	List.AddTail("isnull(");
	List.AddTail("least(");
	//List.AddTail("not like");	//false positives
	List.AddTail("strcmp(");

	//https://dev.mysql.com/doc/refman/5.7/en/encryption-functions.html
	List.AddTail("encode(");
	List.AddTail("encrypt(");
	List.AddTail("decode(");
	List.AddTail("decrypt(");
	List.AddTail("compress(");
	List.AddTail("md5(");
	List.AddTail("sha(");
	List.AddTail("sha1(");
	List.AddTail("sha2(");
	List.AddTail("sha256("); //not yet in mysql

	//https://dev.mysql.com/doc/refman/5.7/en/xml-functions.html
	List.AddTail("extractvalue(");
	List.AddTail("updatexml(");

	//SQL Server
	List.AddTail("collate database_default");
	List.AddTail("collate sql_");
	List.AddTail("collate windows_");

	//SQL Server - Stored Procedures
	List.AddTail("xp_");
	List.AddTail("sp_");
	//these below will be blocked (because the 2 lines above "xp_" & "sp_" will also be detected)
	List.AddTail("xp_cmdshell");
	List.AddTail("xp_reg");
	//List.AddTail("xp_regread");
	//List.AddTail("xp_regwrite");
	//List.AddTail("xp_regdeletekey");
	//List.AddTail("xp_regdeletevalue");
	//List.AddTail("xp_regaddmultistring");
	//List.AddTail("xp_regenumkeys");
	//List.AddTail("xp_regenumvalues");
	//List.AddTail("xp_regremovemultistring");
	List.AddTail("xp_servicecontrol");
	List.AddTail("xp_setsqlsecurity");
	List.AddTail("xp_readerrorlog");
	List.AddTail("xp_controlqueueservice"); //buffer overflow extended procedures
	List.AddTail("xp_createprivatequeue");
	List.AddTail("xp_decodequeuecommand");
	List.AddTail("xp_deleteprivatequeue");
	List.AddTail("xp_deletequeue");
	List.AddTail("xp_displayqueuemesgs");
	List.AddTail("xp_dsinfo");
	List.AddTail("xp_mergelineages");
	List.AddTail("xp_readpkfromqueue");
	List.AddTail("xp_readpkfromvarbin");
	List.AddTail("xp_repl_encrypt");
	List.AddTail("xp_resetqueue");
	List.AddTail("xp_sqlinventory");
	List.AddTail("xp_unpackcab");
	List.AddTail("xp_sprintf");
	List.AddTail("xp_displayparamstmt");
	List.AddTail("xp_enumresult");
	List.AddTail("xp_showcolv");
	List.AddTail("xp_updatecolvbm");
	List.AddTail("xp_execresultset"); //can be used to bypass access control
	List.AddTail("xp_printstatements");
	List.AddTail("xp_peekqueue");
	List.AddTail("xp_proxiedmetadata");
	List.AddTail("xp_displayparamstmt");
	List.AddTail("xp_availablemedia");
	List.AddTail("xp_enumdsn");
	List.AddTail("xp_filelist");
	List.AddTail("sp_password");
	List.AddTail("sp_adduser");
	List.AddTail("sp_addextendedproc");
	List.AddTail("sp_dropextendedproc");
	List.AddTail("sp_add_job"); //sp_add_jobstep
	List.AddTail("sp_start_job");
	List.AddTail("sp_delete_alert");
	List.AddTail("sp_msrepl_startup");

	//SQL Server 2005
	List.AddTail("sp_configure");

	List.AddTail("sp_oa");
	List.AddTail("sp_oacreate");
	List.AddTail("sp_oadestroy");
	List.AddTail("sp_oageterrorinfo");
	List.AddTail("sp_oagetproperty");
	List.AddTail("sp_oamethod");
	List.AddTail("sp_oasetproperty");
	List.AddTail("sp_oastop");

	//MS Access - System Tables
	List.AddTail("msysaces"); //MsysACEs
	List.AddTail("msysobjects");
	List.AddTail("msysqueries");
	List.AddTail("msysrelationships");

	//MySQL - System Tables
	List.AddTail("mysql.");
	List.AddTail("mysql.user");
	List.AddTail("mysql.host");
	List.AddTail("mysql.db");

	//Oracle - System Tables
	List.AddTail(" sys.");
	List.AddTail("sys.all_tables");
	List.AddTail("sys.tab");
	List.AddTail("sys.user_");
	List.AddTail("sys.user_catalog");
	List.AddTail("sys.user_objects");
	List.AddTail("sys.user_tab_columns");
	List.AddTail("sys.user_tables");
	List.AddTail("sys.user_views");
}

void CSignatures::EncodingExploits(CStringList& List)
{
	List.RemoveAll();
	//hex null
	List.AddTail("%00");

	//unicode
	List.AddTail("%u");
	List.AddTail("%u00");
	List.AddTail("%u0000");
	List.AddTail("%U");
	List.AddTail("%U0000");
	List.AddTail("%U00000000");

	List.AddTail("%u0025");		//embedded encoding
	List.AddTail("%U00000025");	//embedded encoding

	//C-style
	List.AddTail("\\o00");
	List.AddTail("\\x00");
	List.AddTail("\\u0000");
	List.AddTail("\\U00000000");

	//C-style recursive
	List.AddTail("\\x5C");
	List.AddTail("\\x5c");
	List.AddTail("\\x5Cx5C");
	List.AddTail("\\x5cx5c");
	List.AddTail("\\x5cx5C");
	List.AddTail("\\x5Cx5c");
	List.AddTail("\\o134");
	List.AddTail("\\o134o134");

	List.AddTail("%%"); //double encoding

	//url missing encoding
	List.AddTail("&amp;"); //html encoded url not decoded by bot
	List.AddTail("='");
	List.AddTail("'&");
	//List.AddTail("'"); //JavaScript's urlEncode does not encode the single quote
}

void CSignatures::EncodingExploits(CMapStringToString& Map)
{
	Map.SetAt("ASP URL encoding issue","%!(([uU]\\h\\h)?\\h\\h)"); //only allow %hh or %uhhhh
	
	Map.SetAt("SQLMap apostrophemask.py","%[Ee][Ff]%[Bb][Cc]%87");
	Map.SetAt("SQLMap apostrophenullencode.py","%00%27");
	Map.SetAt("SQLMap appendnullbyte.py","%00$");
	Map.SetAt("SQLMap overlongutf8.py","%(([Cc]0)|([Ee]0%80)|([Ff]0%80%80)|([Ff]8%80%80%80)|([Ff][Cc]%80%80%80%80))%(([Aa][Aa])|(9[3-7]))");
	Map.SetAt("SQLMap space2mssqlhash.py","%23%0[AaDd]");
	Map.SetAt("SQLMap space2morehash.py","%23.+?%0[AaDd]"); //FUNCTION%23randomText%0A()
	Map.SetAt("SQLMap unmagicquotes.py","%[Bb][Ff]%27"); //http://shiflett.org/blog/2006/jan/addslashes-versus-mysql-real-escape-string

	Map.SetAt("UTF-8 Halfwidth and Fullwidth Forms","%[Ee][Ff]%[Bb][CcDd]%[89AaBb]\\h");	//http://www.utf8-chartable.de/unicode-utf8-table.pl?start=65280&number=128

	//TODO: 4.x - ENCODING - UTF7/16...
	//http://michaelthelin.se/security/2014/06/08/web-security-cross-site-scripting-attacks-using-utf-7.html
	//https://www.notsosecure.com/sql-injection-and-utf-7-encoding/

	//%hh and %u should be together in url (and not one encoded in the other)
	Map.SetAt("MS Unicode 16-bit Embedded","%25u\\h\\h\\h\\h");	//block %25uFFFF query/post data %25u\h\h\h\h
	Map.SetAt("MS Unicode 16-bit Halfwidth and Fullwidth Forms","%u[fF][fF]\\h\\h");	//Halfwidth and Fullwidth characters
	Map.SetAt("MS Unicode 16-bit Replacement Character","%u[fF][fF][fF][dD]");	//replacement character %ufffd
	Map.SetAt("MS Unicode 16-bit Invalid Encoding","%u[fF][fF][fF][eEfF]");	//unicode calculation issue
	Map.SetAt("MS Unicode 32-bit Embedded","%25U\\h\\h\\h\\h\\h\\h\\h\\h");	//block %25UFFFFAAAA query/post data %25U\h\h\h\h\h\h\h\h
	Map.SetAt("MS Unicode 32-bit Replacement Character","%U[fF][fF][fF][fF][fF][fF][fF][dD]");	//replacement character
	Map.SetAt("MS Unicode 32-bit Invalid Encoding","%U[fF][fF][fF][fF][fF][fF][fF][eEfF]");	//unicode calculation issue

	//Map.SetAt("Base64 Payload","^([a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/])*(([a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/]==)|([a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/]=))?$");	//block Base64 encoded query/post data - this also blocks "data" as parameter - also see EnableActiveSync
}

void CSignatures::AuthPasswords(CStringList& List)
{
	//AUTH - Default passwords
	List.RemoveAll();
	List.AddTail("1111");
	List.AddTail("11111");
	List.AddTail("111111");
	List.AddTail("1234");
	List.AddTail("12345");
	List.AddTail("123456");
	List.AddTail("1234567");
	List.AddTail("12345678");
	List.AddTail("123456789");
	List.AddTail("1234567890");
	List.AddTail("54321");
	List.AddTail("adm");
	List.AddTail("admin");
	List.AddTail("administrator");
	List.AddTail("access");
	List.AddTail("account");
	List.AddTail("all");
	List.AddTail("anyone");
	List.AddTail("azerty");
	List.AddTail("backup");
	List.AddTail("control");
	List.AddTail("database");
	List.AddTail("dba");
	List.AddTail("debug");
	List.AddTail("default");
	List.AddTail("develop");
	List.AddTail("developer");
	List.AddTail("development");
	List.AddTail("enter");
	List.AddTail("ftp");
	List.AddTail("ftproot");
	List.AddTail("god");
	List.AddTail("guest");
	List.AddTail("login");
	List.AddTail("master");
	List.AddTail("oracle");
	List.AddTail("oracle8");
	List.AddTail("password");
	List.AddTail("password1");
	List.AddTail("pass");
	List.AddTail("pwrchute");
	List.AddTail("qwerty");
	List.AddTail("root");
	List.AddTail("sa");
	List.AddTail("secret");
	List.AddTail("sql");
	List.AddTail("sqlserver");
	List.AddTail("tech");
	List.AddTail("test");
	List.AddTail("user");
	List.AddTail("web");
	List.AddTail("webmaster");
	List.AddTail("work");
	List.AddTail("www");
}

void CSignatures::AuthAccounts(CStringList& List)
{
	List.RemoveAll();
	List.AddTail("Guest");
	List.AddTail("SQLDebugger");
	List.AddTail("TsInetnetUser");
	List.AddTail("Test");
	List.AddTail("SQL");
	List.AddTail("SQLServer");
	List.AddTail("Webserver");
	List.AddTail("nobody");
	List.AddTail("postmaster");
	List.AddTail("operator");
	List.AddTail("Mail");
	List.AddTail("Replicator");
	List.AddTail("Replication");
	List.AddTail("Debug");
	List.AddTail("DBA");
	List.AddTail("abc");
	List.AddTail("access");
	List.AddTail("admin");
	//List.AddTail("administrator");
	List.AddTail("anon");
	List.AddTail("anonymous");
	List.AddTail("anyone");
	List.AddTail("backup");
	List.AddTail("batch");
	List.AddTail("config");
	List.AddTail("control");
	List.AddTail("data");
	List.AddTail("database");
	List.AddTail("ftp");
	List.AddTail("ftproot");
	List.AddTail("install");
	List.AddTail("login");
	List.AddTail("master");
	List.AddTail("oracle");
	List.AddTail("oracle8");
	List.AddTail("public");
	List.AddTail("pwrchute");
	List.AddTail("recovery");
	List.AddTail("remote");
	List.AddTail("root");
	List.AddTail("router");
	List.AddTail("sa");
	List.AddTail("security");
	List.AddTail("server");
	List.AddTail("service");
	List.AddTail("setup");
	List.AddTail("sybase");
	List.AddTail("test");
	List.AddTail("user");
	List.AddTail("web");
	List.AddTail("webdb");
	List.AddTail("webmaster");
	List.AddTail("www");
	List.AddTail("wwwadmin");
}

void CSignatures::UnixCommands(CStringList& List)
{
	//Default *nix commands
	//List.AddTail("ps");
	List.AddTail("wget"); //too much collateral damage
	List.AddTail("uname");
	//List.AddTail("id");
	List.AddTail("echo");
	List.AddTail("kill");
	List.AddTail("chmod");
	List.AddTail("chgrp");
	List.AddTail("chsh");
	//List.AddTail("cc");
	//List.AddTail("cpp");
	List.AddTail("gcc");
	List.AddTail("g++");
	List.AddTail("python");	//too much collateral damage
	List.AddTail("tclsh");
	List.AddTail("nasm");
	//List.AddTail("perl");	//too much collateral damage: hyperlink.htm
	List.AddTail("traceroute");
	List.AddTail("nmap");	//too much collateral damage
	List.AddTail("lsof");	
	//List.AddTail("mail");
	List.AddTail("inetd.conf");
	List.AddTail("motd");
	List.AddTail("shadow");
	List.AddTail("httpd.conf"); //*/
}

void CSignatures::HTTPVersions(CStringList& List)
{
	List.RemoveAll();
	List.AddTail("");			//HTTP/0.9
	List.AddTail("HTTP/0.9");	//IIS 6+ reports empty version as "HTTP/0.9"
	List.AddTail("HTTP/1.0");
	List.AddTail("HTTP/1.1");
	List.AddTail("HTTP/2.0");
}

void CSignatures::MaliciousHTML(CStringList& List)
{
	List.AddTail("<object");			//deny malicious html
	List.AddTail("<iframe");
	List.AddTail("<link");
	List.AddTail("<applet");
	List.AddTail("<embed");
	List.AddTail("<script");
	List.AddTail("<form");
	List.AddTail("<style");
	List.AddTail("urn:schemas-microsoft-com:time");
	List.AddTail("urn:schemas-microsoft-com:vml");
	List.AddTail("urn:schemas-microsoft-com:xml-data");
	List.AddTail("<meta");
	List.AddTail("<svg");

	//http://html5sec.org/
	List.AddTail("<base");
	List.AddTail("<input");
	List.AddTail("<maction");
	List.AddTail("<frameset");
	//List.AddTail("<comment"); //not effective on our engine
	//List.AddTail("<!--"); //too restrictive
	List.AddTail("<!--#exec");	//https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
	//List.AddTail("<![");	//used in XML
	//List.AddTail("<![data[");
	List.AddTail("<!doctype");
	List.AddTail("<!entity");
	List.AddTail("<!attlist");
	//List.AddTail("<%"); //false positives
	//List.AddTail("<//");	//false positives
	List.AddTail("@import");
	List.AddTail("-o-link");
	List.AddTail("-o-link-source");
	List.AddTail("<animate");
	List.AddTail("<handler");
	List.AddTail("<listener");
	List.AddTail("<?xml-stylesheet");
	List.AddTail("<onevent");
	List.AddTail("<stylesheet");
	List.AddTail("<eval");
	List.AddTail("<vmlframe");
	List.AddTail("<scriptlet");
	List.AddTail("<import");
	List.AddTail("<?import");
	List.AddTail("view-source:");
	List.AddTail("<event-source");

	//Howest Honeypot Project 2015
	List.AddTail("<html");
	List.AddTail("<body");
	List.AddTail("<area");
	List.AddTail("<math");
}

void CSignatures::ColdFusionExploits(CStringList& List)
{
	List.AddTail("cf_setdatasourceusername()");
	List.AddTail("cf_setdatasourcepassword()");
	List.AddTail("cf_iscoldfusiondatasource()");
	List.AddTail("cfusion_getodbcdsn()");
	List.AddTail("cfusion_dbconnections_flush()");
	List.AddTail("cfusion_encrypt()");
	List.AddTail("cfusion_setodbcini()");
	List.AddTail("cfusion_settings_refresh()");
	List.AddTail("cfusion_verifymail()");
}

void CSignatures::PHPExploits(CStringList& List)
{
	List.AddTail("includedir=");
	List.AddTail("_phplib[libdir]");
	List.AddTail("<?php"); //PHP injection

	//http://php.net/manual/en/wrappers.php
	List.AddTail("data://");
	List.AddTail("expect://");
	List.AddTail("glob://");
	List.AddTail("ogg://");
	List.AddTail("phar://");
	List.AddTail("php://");
	List.AddTail("rar://");
	List.AddTail("ssh2://");
	List.AddTail("zlib://");

	List.AddTail("phpinfo()");
	List.AddTail("base64_decode(");
	List.AddTail("eval(");
	List.AddTail("exec(");
	List.AddTail("system(");
	List.AddTail("passthru(");
	List.AddTail("${echo");
	List.AddTail("${exit");
}

void CSignatures::RemoteFileInclusion(CStringList& List)
{
	List.AddTail("=data:"); //RFC 2397
	List.AddTail("=mhtml:");
	List.AddTail("=file://");
	List.AddTail("=ftp://");
	List.AddTail("=gopher://");
	List.AddTail("=http://");
	List.AddTail("=https://");
	List.AddTail("=[data:"); //RFC 2397
	List.AddTail("=[mhtml:");
	List.AddTail("=[file://");
	List.AddTail("=[ftp://");
	List.AddTail("=[gopher://");
	List.AddTail("=[http://");
	List.AddTail("=[https://");

	List.AddTail("dir=http://");
	List.AddTail("dir]=http://");
	List.AddTail("doc=http://");
	List.AddTail("doc]=http://");
	List.AddTail("document=http://");
	List.AddTail("document]=http://");
	List.AddTail("file=http://");
	List.AddTail("file]=http://");
	List.AddTail("folder=http://");
	List.AddTail("folder]=http://");
	List.AddTail("root=http://");
	List.AddTail("root]=http://");
	List.AddTail("path=http://");
	List.AddTail("path]=http://");
	List.AddTail("inc=http://");
	List.AddTail("inc]=http://");
	List.AddTail("_incl=http://");
	List.AddTail("_incl]=http://");
	List.AddTail("include=http://");
	List.AddTail("include]=http://");

	List.AddTail("base=http://");
	List.AddTail("main=http://");
	List.AddTail("name=http://");
	List.AddTail("page=http://");
	List.AddTail("pdf=http://");
	List.AddTail("pg=http://");
	List.AddTail("style=http://");
	List.AddTail("template=http://");

	List.AddTail("=test??");	// /common.inc.php?CFG[libdir]=test??
}

void CSignatures::PaymentCards(CMapStringToString& Map)
{
	//http://www.sans.org/security-resources/idfaq/snort-detect-credit-card-numbers.php
	//Map.SetAt("Visa","4\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	//Map.SetAt("Mastercard","5\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	//Map.SetAt("Discover","6011[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	//Map.SetAt("American Express","3\\d\\d\\d[ \\-]?\\d\\d\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d\\d");

	//http://www.richardsramblings.com/regex/credit-card-numbers/
	Map.SetAt("Visa","4\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	Map.SetAt("Mastercard","5[1-5]\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	Map.SetAt("Discover","6((011)|(22\\d)|(4[4-9]\\d)|(5\\d\\d))[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	Map.SetAt("JCB","35\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
	Map.SetAt("American Express","3[47]\\d\\d[ \\-]?\\d\\d\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d\\d");
	Map.SetAt("China UnionPay","62[0-5]\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d[ \\-]?\\d\\d\\d\\d");
}

void CSignatures::ErrorPages(CStringList& List)
{
	/*
	 * Server encountered an internal error. To get more info turn on customErrors in the server's config file.
	 * <font face="Arial" size=2> <p>Microsoft VBScript compilation </font> <font face="Arial" size=2>error '800a0409'</font> <p> <font face="Arial" size=2>Unterminated string constant</font> <p> ... 
	 */
	List.AddTail("Microsoft VBScript compilation");
	List.AddTail("Microsoft VBScript runtime");

	//request for /.soap -> System.Runtime.Remoting.RemotingException: Requested Service not found
	List.AddTail("System.Runtime.Remoting.RemotingException");

	//request for /.aspq -> This type of page is not served, but contains .NET version
	List.AddTail("Microsoft .NET Framework Version");

	//Joe McCray site:targetcompany.com
	List.AddTail("Microsoft OLE DB Provider for SQL Server"); //j0e
	List.AddTail("Microsoft JET Database Engine"); //j0e
	List.AddTail("Type mismatch"); //j0e
	List.AddTail("You have an error in your SQL syntax"); //j0e
	List.AddTail("Invalid SQL statement or JDBC"); //j0e
	List.AddTail("DorisDuke error"); //j0e
	List.AddTail("OleDbException"); //j0e
	List.AddTail("JasperException"); //j0e
	List.AddTail("Fatal Error"); //j0e
	List.AddTail("supplied argument is not a valid MySQL"); //j0e
	List.AddTail("mysql_"); //j0e
	List.AddTail("mysqli_");
	List.AddTail("ODBC"); //j0e
	List.AddTail("JDBC"); //j0e
	List.AddTail("ORA-00921"); //j0e
	List.AddTail("ADODB"); //j0e

	//TODO: 4.x - information leakage - owasp core ruleset?
}

void CSignatures::ErrorPages(CMapStringToString& Map)
{
	CStringList errorpages;
	CSignatures::ErrorPages(errorpages);
	CString pattern = "(" + CStringHelper::ToString(errorpages,")|(") + ")";
	pattern.Replace("(ODBC)|(JDBC)","(O|JDBC)");
	pattern.Replace("(mysql_)|(mysqli_)","(mysqli?_)");
	pattern.Replace("(Microsoft VBScript compilation)|(Microsoft VBScript runtime)","(Microsoft VBScript (compilation)|(runtime))");
	Map.SetAt("Error Page",pattern);
}

CString CSignatures::RegexPatternCommandLine(CString command, CString parameter)
{
	//curl(\b)+(-(\w))?(\b)*(\")?http
	return command + "((\\b)+-(\\w)?(\\b[a-zA-Z0-9/\\\\]+)?)*(\\b)+(\\\")?" + parameter;
}

CString CSignatures::RegexPatternHtmlWhitespace()
{
	return "(\\b|\\n|[\\f\\v])*";
}

CString CSignatures::RegexPatternHtmlAttribute(CString attribute)
{
	return "(\\b|\\n|[\\f\\v\"\'`/])" + attribute + "(\\b|\\n|[\\f\\v])*=";
}

CString CSignatures::RegexPatternHtmlAttribute(CString attribute, CString value)
{
	return RegexPatternHtmlAttribute(attribute) + "(\\b|\\n|[\\f\\v])*(\"|\')*" + value;
}

CString CSignatures::RegexPatternHtmlEncoded(CString text)
{
	CString ret("");
	int length = text.GetLength();
	TCHAR c;
	TCHAR U;
	TCHAR l;
	char bufint[34] = "\0";
	for(int i=0; i<length; i++){
		c = text[i];
		U = toupper(c);
		l = tolower(c);
		ret += "((";
		if(U!=l){
			//char (C|c[\\]?)
			ret+=U; ret+="|"; ret+=l; ret+="[\\\\]?)|(&#(";
			//decimal &#0*((DEC)|(dec));?
			ret += "(0*("; ret += _itoa((int)U,bufint,10); ret += ")|(";	ret += _itoa((int)l,bufint,10); ret += "))|";
			//hex &#X|x0*((HEX)|(hex));?
			ret += "(X|x0*(";	ret += RegexPatternHexIgnoreCase(_itoa((int)U,bufint,16)); ret += ")|("; ret += RegexPatternHexIgnoreCase(_itoa((int)l,bufint,16)); ret += "))";
		}else{
			//char (c[\\]?)
			ret += c; ret+= "[\\\\]?)|(&#(";
			//decimal &#0*dec;?
			ret += "(0*"; ret += _itoa((int)c,bufint,10); ret += ")|";
			//hex &#X|x0*hex;?
			ret += "(X|x0*"; ret += RegexPatternHexIgnoreCase(_itoa((int)c,bufint,16)); ret += ")";
		}

		ret += ");?))";
	}

	//some optimizations (hex uppercase/lowercase shorter)
	CString hex;
	for(int h=0; h<10; h++){
		hex = _itoa((int)h,bufint,16);
		ret.Replace("(4" + hex + ")|(6" + hex + ")","(4|6" + hex + ")");
		ret.Replace("(5" + hex + ")|(7" + hex + ")","(5|7" + hex + ")");
	}
	for(int h=10; h<16; h++){
		hex = _itoa((int)h,bufint,16);
		l = tolower(hex[0]);
		U = toupper(hex[0]);
		hex = U; hex+= '|'; hex += l;
		ret.Replace("(4" + hex + ")|(6" + hex + ")","(4|6" + hex + ")");
		ret.Replace("(5" + hex + ")|(7" + hex + ")","(5|7" + hex + ")");
	}
	return ret;
}

CString CSignatures::RegexPatternHexIgnoreCase(CString text)
{
	CStringHelper::Safe_MakeLower(text);
	text.Replace(_T("a"),_T("A|a"));
	text.Replace(_T("b"),_T("B|b"));
	text.Replace(_T("c"),_T("C|c"));
	text.Replace(_T("d"),_T("D|d"));
	text.Replace(_T("e"),_T("E|e"));
	text.Replace(_T("f"),_T("F|f"));
	return text;
}

CString CSignatures::RegexPatternHttpHeader(CString header, CString value)
{
	return _T("^(.+\\n)?") + header + _T(":(\\b)*") + value;
}

CString CSignatures::RegexPatternHttpHeaderOrder(CString header1, CString header2)
{
	return RegexPatternHttpHeader(header1,_T("(.*\\n)+") + header2 + _T(":"));
}
