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
// HTTPFirewall.cpp: implementation of the CHTTPFirewall class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "HTTPFirewall.h"
#include "MIME.h"
#include "ValidationScan.h"
#include "FormsAuthenticationScan.h"
#include "DataUrl.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CHTTPFirewall::CHTTPFirewall(CHTTPFirewallSettings& _Settings, CLogger& _logger): Settings(_Settings),CFirewall(_Settings,_logger)
{

}

CHTTPFirewall::~CHTTPFirewall()
{

}

Action CHTTPFirewall::ScanRawHeaders(CString &Headers)
{
	Action action;
	CString strhLog = Headers.Left(4096); //for log file

	//HEADERS: validate
	if(Settings.Experimental.Headers.InputValidation){
		WebParam& Parameters = Settings.Headers.Validation.Headers;

		CStringList list; CStringHelper::Split(list,Headers,CRLF);
		CMapStringToString map;	
		CStringHelper::Split(list,':',map);
		POSITION pos = map.GetStartPosition();
		CString key;
		CString val;
		while(pos!=NULL){
			map.GetNextAssoc(pos,key,val);
			key += ':';
			val = val.TrimLeft();

			//HEADER: name validation
			if(Settings.Experimental.Headers.NameRequireRegex.Action){
				CAtlRegExp<>* regex = Settings.regex_cache.Lookup(Settings.Experimental.Headers.NameRequireRegex.Value);
				if(regex!=NULL){ //NULL = regex syntax error
					CAtlREMatchContext<> mc;
					if(!regex->Match(key,&mc)){
						action.Set(Settings.Experimental.Headers.NameRequireRegex.Action);
						Alert("Header name not valid '" + key + "'",Settings.Experimental.Headers.NameRequireRegex.Action);
					}
				}
			}
			
			//HEADER: monitor new headers
			if(Settings.Experimental.Headers.LogNewHeaders && !Parameters.Cache.IsFull()){
				if(!Parameters.Cache.Exists(key) && !Settings.Headers.Validation.HasValidator(Parameters,key)){
					CString pattern = Settings.Headers.Validation.MatchPattern(val);
					Parameters.Cache.Add(key,pattern);
					DebugLog(key,pattern + " ; " + val,Headers,"Headers.New.log",true);
				}
			}

			//HEADER: input validation
			if(!Settings.Headers.Validation.Validate(Parameters,key,val)){
				action.Set(Settings.Experimental.Headers.InputValidation);
				Alert("Header validation failed '" + key + "'",Settings.Experimental.Headers.InputValidation);

				//HEADERS: monitor failed rules
				if(Settings.Experimental.Headers.LogValidationFailures && !Settings.Experimental.Headers.ValidationFailures.IsFull()){
					if(!Settings.Experimental.Headers.ValidationFailures.Exists(key,val)){
						Settings.Experimental.Headers.ValidationFailures.Add(key,val);
						DebugLog(key,val,Headers,"Headers.Failed.log",true);
					}
				}

			}
		}
	}

	//HEADERS: generic header length
	if(Settings.Headers.MaxLength.Action && Settings.Headers.MaxLength.Value>0){
		if(ScanVariableLength(Headers,Settings.Headers.MaxLength.Value,CR,LF)){
			action.Set(Settings.Headers.MaxLength.Action);
			Alert("Maximum generic header length exceeded",Settings.Headers.MaxLength.Action);
		}
	}
		
	//HEADERS: check for encoding abuse
	if(Settings.Headers.EncodingExploits){

		if(DenySequences(Headers,Settings.EncodingExploits.Keywords,"Encoding exploit in headers '","'",Settings.Headers.EncodingExploits)){
			action.Set(Settings.Headers.EncodingExploits);
		}

		if(DenyRegex(Headers,Settings.EncodingExploits.Regex,"Encoding exploit in headers '","'",Settings.Headers.EncodingExploits)){
			action.Set(Settings.Headers.EncodingExploits);
		}
	}
	
	Headers = CURL::Decode(Headers);

	if(Settings.Headers.EncodingExploits){

		//HEADERS: Deny encoding exploits (normalize twice, except for '+', and reject if change occurs)
		if(Settings.EncodingExploits.ScanDoubleEncoding){
			if(CanHexDecode(Headers,false)){
				action.Set(Settings.Headers.EncodingExploits);
				Alert("Encoding exploit in headers (embedded encoding)",Settings.Headers.EncodingExploits);
			}
		}
		
		//HEADERS: Invalid UTF-8
		if(Settings.EncodingExploits.ScanInvalidUTF8){
			if(!CUnicode::IsValidUTF8(Headers)){
				action.Set(Settings.Headers.EncodingExploits);
				Alert("Encoding exploit in headers (invalid UTF-8)",Settings.Headers.EncodingExploits);
			}
		}
	}

	//HEADERS: Deny directory traversal (parent path)
	if(Settings.Headers.DirectoryTraversal){
		if(ScanDirectoryTraversal(Headers)){
			action.Set(Settings.Headers.DirectoryTraversal);
			Alert("Directory traversal not allowed in headers",Settings.Headers.DirectoryTraversal);
		}
	}

	//HEADERS: Deny high bit characters (shellcode)
	if(Settings.Headers.HighBitShellcode){
		if(ScanHighBitShellCode(Headers)){
			action.Set(Settings.Headers.HighBitShellcode);
			Alert("High bit characters (shellcode) not allowed in headers",Settings.Headers.HighBitShellcode);
		}
	}

	CStringHelper::Safe_MakeLower(Headers);

	//HEADERS: Deny SQL injection (words in list should be lowercase)
	if(Settings.Headers.SQLInjection){	
		int sqlcount(Settings.SQLi.Keywords.Find(";")!=NULL?-1:0);
		if(Settings.SQLi.Keywords.Find("/*")!=NULL)	//Accept: */*
			sqlcount--;
		if(Settings.SQLi.Keywords.Find("*/")!=NULL)
			sqlcount--;
		CStringList Matches;
		sqlcount += ScanSQLInjection(Headers,Settings.SQLi.Keywords,Matches,Settings.SQLi.NormalizeWhitespace,Settings.SQLi.ReplaceNumericWithOne);
		if(sqlcount>0){
			if(sqlcount>Settings.SQLi.AllowedCount){
				action.Set(Settings.Headers.SQLInjection);
				Alert("Possible SQL injection in headers (" + CStringHelper::ToString(Matches,",") + ")",Settings.Headers.SQLInjection);
			}else{
				logger.Append("WARNING: SQL keyword found in headers (" + CStringHelper::ToString(Matches,",") + "). " + CStringHelper::Safe_IntToAscii(Settings.SQLi.AllowedCount - sqlcount + 1) + " more will block request.");
			}
		}
	}

	//HEADERS: Deny certain sequences (words in list should be lowercase)
	if(Settings.Headers.DenySequences.Action){
		if(DenySequences(Headers,Settings.Headers.DenySequences.List,"'","' not allowed in headers",Settings.Headers.DenySequences.Action)){
			action.Set(Settings.Headers.DenySequences.Action);
		}
	}

	//HEADERS: Deny regex
	if(Settings.Headers.DenyRegex.Action){
		if(DenyRegex(Headers,Settings.Headers.DenyRegex.Map,"'","' regex not allowed in headers",Settings.Headers.DenyRegex.Action)){
			action.Set(Settings.Headers.DenyRegex.Action);
		}
	}

	if (!action.IsEmpty()){
		logger.AppendEscape(strhLog);
	}

	return action;
}

Action CHTTPFirewall::ScanRawData(CString &Data, CString& IP)
{
	//return ScanEntity(Data,CString("multipart/form-data; boundary=---------------------------"),IP); //for testing on IIS 5
	return ScanEntity(Data,CString("application/x-www-form-urlencoded"),IP);
}

Action CHTTPFirewall::ScanEntity(CString &Data, CString ContentType, CString& IP, unsigned short depth)
{
	Action action;
	//logger.Append(Data);
	CMIME mime(ContentType);

	if(mime.IsMultiPart && depth<5){
		//types of multipart:
		//https://msdn.microsoft.com/en-us/library/ms527355%28v=exchg.10%29.aspx

		//multiple entities
		depth++;
		if(mime.Boundary.GetLength()>0){

			CStringList entities;
			CStringHelper::Split(entities, Data, CRLF + mime.Boundary);
			CValidationScan* scan = NULL;
			CFormsAuthenticationScan* formAuth = NULL;
			if(mime.IsMultiPartFormData){
				scan = new CValidationScan();
				scan->isPHP = Settings.Engine.IsPHP;
				scan->removeLeadingSpace = Settings.Engine.IsPHP;
				scan->scanPollution = Settings.Post.Parameters.Pollution>Action::Disabled;
				if(Settings.Post.Parameters.NameRequireRegex.Action)		
					scan->nameValidator = Settings.regex_cache.Lookup(Settings.Post.Parameters.NameRequireRegex.Value);
				if(Settings.Post.Parameters.InputValidation)
					scan->inputValidation = &(Settings.ApplicationParameters);

				if(depth==1){ //only scan top level multipart/form-data
					formAuth = new CFormsAuthenticationScan();
					formAuth->isPHP = Settings.Engine.IsPHP;
					formAuth->removeLeadingSpace = true;
				}
			}

			//recursive
			POSITION pos = entities.GetHeadPosition();
			int posstart;
			int posend;
			while(pos!=NULL){
				CString entity = entities.GetNext(pos);

				//content-type
				CString ct = CMIME::GetHeader(entity,"Content-Type:","text/plain" /* default according to RFC */);
				CString name = "";

				//Content-Disposition in multipart/form-data
				if(mime.IsMultiPartFormData){
					CString cd = CMIME::GetHeader(entity,"Content-Disposition:","");
					//extract parameter name from Content-Disposition
					posstart = cd.Find("; name=\""); //length=8
					if(posstart>-1){
						posend = cd.Find("\"",posstart+8);
						if(posend>-1)
							name = cd.Mid(posstart+8,posend-posstart-8);
					}
				}

				//data
				posstart = entity.Find(CRLFCRLF);
				if(posstart>0 && posstart<entity.GetLength()-4)
					entity = entity.Mid(posstart+4);

				//scan input validation multipart/form-data
				if(name.GetLength()>0){
					if(scan)
						scan->Scan(name,entity,Settings.ApplicationParameters.Post);
					if(formAuth)
						formAuth->Scan(name,entity,Settings.Authentication.UsernameFields,Settings.Authentication.PasswordFields);
				}

				//logger.Append(ct);
				action |= ScanEntity(entity,ct,IP,depth);
			}

			//validation scan
			if(scan){
				//process input validation results
				if(scan->result.pollutedParameters.GetCount()>0){
					action.Set(Settings.Post.Parameters.Pollution);
					Alert("Parameter pollution in data '" + CStringHelper::ToString(scan->result.pollutedParameters,",") + "'",Settings.Post.Parameters.Pollution);
				}
				if(scan->result.failedParameters.GetCount()>0){
					action.Set(Settings.Post.Parameters.InputValidation);
					Alert("Parameter validation failed in data '" + CStringHelper::ToString(scan->result.failedParameters,",") + "'",Settings.Post.Parameters.InputValidation);
				}
				if(scan->result.badParameters.GetCount()>0){
					action.Set(Settings.Post.Parameters.NameRequireRegex.Action);
					Alert("Parameter name not valid in data '" + CStringHelper::ToString(scan->result.badParameters,",") + "'",Settings.Post.Parameters.NameRequireRegex.Action);
				}
				delete scan;
			}

			//Forms Authentication scan
			if(formAuth){
				if(Settings.Authentication.FormParameterPollution){
					if(formAuth->IsUsernamePolluted){
						action.Set(Settings.Authentication.FormParameterPollution);
						Alert("Username parameter pollution",Settings.Authentication.FormParameterPollution);
					}
					if(formAuth->IsPasswordPolluted){
						action.Set(Settings.Authentication.FormParameterPollution);
						Alert("Password parameter pollution",Settings.Authentication.FormParameterPollution);
					}
				}

				if(formAuth->User!="" && formAuth->HasPass){
					logger.Append("Forms Authentication");
					action |= ScanAuthentication(formAuth->User,formAuth->Pass,IP);
				}

				delete formAuth;
			}
		}else{
			//no boundary? scan as x-www-form-urlencoded
			if(Settings.Post.RFCCompliant){
				action.Set(Settings.Post.RFCCompliant);
				Alert("Data is not RFC compliant (Boundary mismatch)",Settings.Post.RFCCompliant);
			}
			action |= ScanEntity(Data,CString("application/x-www-form-urlencoded"),IP);
		}
	}else{
		//single entity

		//DATA: variable size
		if(Settings.Post.MaxVariableLength.Action && Settings.Post.MaxVariableLength.Value>0 && Data.Find('=')!=-1){
			if(	( mime.IsUrlEncoded && Data.Find('=')!=-1 && ScanVariableLength(Data,Settings.Post.MaxVariableLength.Value,'&','&') ) ||
				( mime.IsTextPlain && depth==0 && ScanVariableLength(Data,Settings.Post.MaxVariableLength.Value,CR,LF) )
			){
				action.Set(Settings.Post.MaxVariableLength.Action);
				Alert("Maximum variable length exceeded in data",Settings.Post.MaxVariableLength.Action);
			}
		}

		if(mime.IsUrlEncoded){

			//DATA: Parameter pollution
			action |= ScanParameters(Data,Settings.Post.Parameters,Settings.ApplicationParameters.Post, "data");

			//DATA: Forms Authentication
			if(Settings.Authentication.ScanForms && depth==0){ //skip embedded in multipart
				action |= ScanFormsAuthentication(Data,IP);
			}

			if(Settings.Post.RFCCompliant){
				if(ContentType.GetLength()==0){
					//no content type given. Allowed by RFC 2616, but recommended to have this header in RFC 7231 (section 3.1.1.5).
					action.Set(Settings.Post.RFCCompliant);
					Alert("Data is not RFC compliant (missing content-type)",Settings.Post.RFCCompliant);
				}else{
					//only when x-www-form-urlencoded
					if(!CURL::IsUrlSafe(Data)){
						action.Set(Settings.Post.RFCCompliant);
						Alert("Data is not RFC compliant (x-www-form-urlencoded mismatch)",Settings.Post.RFCCompliant);
					}
				}
			}

			//DATA: check for encoding abuse
			if(Settings.Post.EncodingExploits){

				if(DenySequences(Data,Settings.EncodingExploits.Keywords,"Encoding exploit in data '","'",Settings.Post.EncodingExploits)){
					action.Set(Settings.Post.EncodingExploits);
				}

				if(DenyRegex(Data,Settings.EncodingExploits.Regex,"Encoding exploit in data '","'",Settings.Post.EncodingExploits)){
					action.Set(Settings.Post.EncodingExploits);
				}
			}

			Data = CURL::Decode(Data);

			if(Settings.Post.EncodingExploits){

				//DATA: Deny encoding exploits (normalize twice, except for '+', and reject if change occurs)
				if(Settings.EncodingExploits.ScanDoubleEncoding){
					if(CanHexDecode(Data,false)){
						action.Set(Settings.Post.EncodingExploits);
						Alert("Encoding exploit in data (embedded encoding)",Settings.Post.EncodingExploits);
					}		
				}

				//DATA: Invalid UTF-8
				if(Settings.EncodingExploits.ScanInvalidUTF8){
					if(!CUnicode::IsValidUTF8(Data)){
						action.Set(Settings.Post.EncodingExploits);
						Alert("Encoding exploit in data (invalid UTF-8)",Settings.Post.EncodingExploits);
					}
				}
			}

		}else if(mime.IsUTF8Encoded /* application/x-www-UTF8-encoded */){

			//DATA: Invalid UTF-8
			if(Settings.Post.EncodingExploits && Settings.EncodingExploits.ScanInvalidUTF8){
				if(!CUnicode::IsValidUTF8(Data)){
					action.Set(Settings.Post.EncodingExploits);
					Alert("Encoding exploit in data (invalid UTF-8)",Settings.Post.EncodingExploits);
				}
			}
		}

		if(!mime.IsBinary){

			//DATA: Scan Data Urls
			if(Settings.Experimental.Post.ScanDataUrl && depth<5){
				CStringList DataUrls;
				CDataUrl::Extract(Data,DataUrls);
				POSITION pos = DataUrls.GetHeadPosition();
				while(pos!=NULL){
					CDataUrl du(DataUrls.GetNext(pos));
					//TODO: EXPERIMENTAL - Scan Data Urls
					DebugLog(du.ContentType,du.ToString(),du.Entity,"DataUrls.log",true);
					ScanEntity(du.Entity,du.ContentType,IP,depth + 1);
				}
			}

			//DATA: Deny directory traversal (parent path)
			if(Settings.Post.DirectoryTraversal){
				if(ScanDirectoryTraversal(Data)){
					action.Set(Settings.Post.DirectoryTraversal);
					Alert("Directory traversal not allowed in data",Settings.Post.DirectoryTraversal);
				}
			}

			//DATA: Deny high bit characters (shellcode)
			if(Settings.Post.HighBitShellcode){
				if(ScanHighBitShellCode(Data)){
					action.Set(Settings.Post.HighBitShellcode);
					Alert("High bit characters (shellcode) not allowed in data",Settings.Post.HighBitShellcode);
				}
			}

		}

		CString data(Data);//copy
		CStringHelper::Safe_MakeLower(data);

		if(!mime.IsBinary){

			//DATA: Deny SQL injection (words in list should be lowercase)
			if(Settings.Post.SQLInjection){
				int sqlcount(0);
				CStringList Matches;
				sqlcount += ScanSQLInjection(data,Settings.SQLi.Keywords, Matches,Settings.SQLi.NormalizeWhitespace,Settings.SQLi.ReplaceNumericWithOne);
				if(sqlcount>0){
					if(sqlcount>Settings.SQLi.AllowedCount){
						action.Set(Settings.Post.SQLInjection);
						Alert("Possible SQL injection in data (" + CStringHelper::ToString(Matches,",") + ")",Settings.Post.SQLInjection);
					}else{
						logger.Append("WARNING: SQL keyword found in data (" + CStringHelper::ToString(Matches,",") + "). " + CStringHelper::Safe_IntToAscii(Settings.SQLi.AllowedCount - sqlcount + 1) + " more will block request.");
					}
				}
			}

		}

		//DATA: deny certain sequences (list should be lowercase)
		if(Settings.Post.DenySequences.Action){
			if(DenySequences(data,Settings.Post.DenySequences.List,"'","' not allowed in data",Settings.Post.DenySequences.Action)){
				action.Set(Settings.Post.DenySequences.Action);
			}
		}

		//DATA: deny regex
		if(Settings.Post.DenyRegex.Action){
			if(DenyRegex(data,Settings.Post.DenyRegex.Map,"'","' regex not allowed in data",Settings.Post.DenyRegex.Action)){
				action.Set(Settings.Post.DenyRegex.Action);
			}
		}

		if(!action.IsEmpty() && Settings.Post.LogLength>0){
			logger.AppendEscape(Data.Left(Settings.Post.LogLength));
		}

	}
	return action;
}

Action CHTTPFirewall::ScanAccount(CString &User)
{
	Action action;
	if(User==""){
		return action;
	}else{
		CString USER(User);
		CStringHelper::Safe_MakeUpper(USER);

		//AUTH - block logon attempts for certain critical accounts
		if(Settings.Authentication.SystemAccounts){
			CString UserLeft = USER.Left(5);
			if(	UserLeft=="IUSR_" ||	//InternetUser
				UserLeft=="IWAM_" ||	//InternetWAM
				UserLeft=="VUSR_" ||	//Visual studio server components
				USER=="SYSTEM" ||		//SYSTEM account
				USER=="KRBTGT" ||		//Kerberos
				USER=="ASPNET" ||		//ASP.NET (out of process)
				USER=="ASPNETUSER" ||	//ASP.NET (out of process) Windows 2003
				USER=="TSINTERNETUSER" ||//Terminal services account (internet account)
				USER=="NETWORK SERVICE"){
					action.Set(Settings.Authentication.SystemAccounts);
					Alert("Attempt to authenticate with system critical account",Settings.Authentication.SystemAccounts);
			}
		}

		//AUTH - only allow certain accounts
		if(Settings.Authentication.AllowAccounts.Action){
			if(!IsInListCompareNoCase(User,Settings.Authentication.AllowAccounts.List)){
				action.Set(Settings.Authentication.AllowAccounts.Action);
				Alert("Account not in allowed list",Settings.Authentication.AllowAccounts.Action);
			}
		}

		//AUTH - Deny certain accounts
		if(Settings.Authentication.DenyAccounts.Action){
			if(IsInListCompareNoCase(User,Settings.Authentication.DenyAccounts.List)){
				action.Set(Settings.Authentication.DenyAccounts.Action);
				Alert("Account not allowed to authenticate",Settings.Authentication.DenyAccounts.Action);
			}
		}
		return action;
	}
}

Action CHTTPFirewall::ScanFilename(CFileName &fn)
{
	Action action;
	char c;

	//FILENAME: Deny default document
	if(Settings.Filename.DefaultDocument){
		if(fn.FileName == ""){
			action.Set(Settings.Filename.DefaultDocument);
			Alert("Default document not allowed",Settings.Filename.DefaultDocument);
		}
	}

	//FILENAME: Deny certain characters in the filename (characters are case sensitive!)
	if(Settings.Filename.Characters.Action){
		for(int i=0;i<Settings.Filename.Characters.Value.GetLength();i++){
			c = Settings.Filename.Characters.Value.GetAt(i);
			if(DenyChar(fn.FileName,c,"'" + CString(c) + "' not allowed in filename",Settings.Filename.Characters.Action))
				action.Set(Settings.Filename.Characters.Action);
		}
	}

	//FILENAME: Deny certain cgi applications (applications in list should be lowercase).
	if(Settings.Filename.Deny.Action){
		if(DenySequences(fn.FileNameLCase,Settings.Filename.Deny.List,"accessing/running '","' file",Settings.Filename.Deny.Action)){
			action.Set(Settings.Filename.Deny.Action);
		}
	}

	//EXTENSION: Only allow certain extensions (extensions in the list should be lowercase)
	if(Settings.Extensions.Allow.Action){
		if(!IsInList(fn.ExtensionLCase,Settings.Extensions.Allow.List)){
			action.Set(Settings.Extensions.Allow.Action);
			Alert("accessing/running '" + fn.Extension + "' file",Settings.Extensions.Allow.Action);
		}
	}

	//EXTENSION: Deny certain extensions (extensions in the list should be lowercase)
	if(Settings.Extensions.Deny.Action){
		if(DenySequences(fn.ExtensionLCase,Settings.Extensions.Deny.List,"accessing/running '","' file",Settings.Extensions.Deny.Action)){
			action.Set(Settings.Extensions.Deny.Action);
		}
	}

	return action;
}

Action CHTTPFirewall::ScanURL(const char *p)
{
	Action action;
	CString URL(p);
	CStringHelper::Safe_MakeLower(URL);

	//URL: Only allow certain characters as the start of a URL (list should be lowercase)
	if(Settings.URL.Allow.Action){
		if(!IsStartInList(URL,Settings.URL.Allow.List)){
			action.Set(Settings.URL.Allow.Action);
			Alert("URL not in allowed list",Settings.URL.Allow.Action);
		}
	}

	//URL: Deny parent path
	if (Settings.URL.ParentPath){
		if(DenyString(p,"..","'..' not allowed in URL (parent path)",Settings.URL.ParentPath)){
			action.Set(Settings.URL.ParentPath);
		}
	}

	//URL: Deny trailing dot in directory
	if (Settings.URL.TrailingDotInDir){
		if(DenyString(p,"./","'./' not allowed in URL (trailing dot on a directory name)",Settings.URL.TrailingDotInDir)){
			action.Set(Settings.URL.TrailingDotInDir);
		}
	}
	
	//URL: Deny backslash
	if (Settings.URL.Backslash){
		if(DenyChar(p,'\\',"'\\' not allowed in URL (backslashes)",Settings.URL.Backslash)){
			action.Set(Settings.URL.Backslash);
		}
	}

	//URL: Deny alternate stream access
	if (Settings.URL.AlternateStream){
		if(DenyChar(p,':',"':' not allowed in URL (alternate stream access)",Settings.URL.AlternateStream)){
			action.Set(Settings.URL.AlternateStream);
		}
	}

	//URL: Deny escaping
	if (Settings.URL.Escaping){
		if(DenyChar(p,'%',"'%' not allowed in URL (hex encoding)",Settings.URL.Escaping)){
			action.Set(Settings.URL.Escaping);
		}
	}

	//URL: Deny running multiple applications
	if (Settings.URL.MultipleCGI){
		if(DenyChar(p,'&',"'&' not allowed in URL (running multiple CGI processes in single request)",Settings.URL.MultipleCGI)){
			action.Set(Settings.URL.MultipleCGI);
		}
	}
	
	//URL: Deny certain characters
	if(Settings.URL.Characters.Action){
		char c;
		for(int i=0;i<Settings.URL.Characters.Value.GetLength();i++){
			c = Settings.URL.Characters.Value.GetAt(i);
			if(DenyChar(p,c,"'" + CString(c) + "' not allowed in URL",Settings.URL.Characters.Action))
				action.Set(Settings.URL.Characters.Action);
		}
	}

	//URL: Deny bad relative url parsers (with // in path)
	if (Settings.URL.BadParser){
		if(CURL::IsBadUrlParser(URL)){
			action.Set(Settings.URL.BadParser);
			Alert("Bad relative url parser",Settings.URL.BadParser);
		}
	}

	//URL: Deny high bit characters (shellcode)
	if(Settings.URL.HighBitShellcode){
		if(ScanHighBitShellCode(p)){
			action.Set(Settings.URL.HighBitShellcode);
			Alert("High bit characters (shellcode) not allowed in URL",Settings.URL.HighBitShellcode);
		}
	}

	//URL: Deny special whitespace characters
	if(Settings.URL.SpecialWhitespace){
		if(DenySpecialWhitespace(p, " not allowed in URL",Settings.URL.SpecialWhitespace)){
			action.Set(Settings.URL.SpecialWhitespace);
		}
	}

	//URL: Deny certain sequences (list should be lowercase)
	if(Settings.URL.DenySequences.Action){
		if(DenySequences(URL,Settings.URL.DenySequences.List,"'","' not allowed in URL",Settings.URL.DenySequences.Action)){
			action.Set(Settings.URL.DenySequences.Action);
		}
	}

	//URL: deny regex
	if(Settings.URL.DenyRegex.Action){
		if(DenyRegex(URL,Settings.URL.DenyRegex.Map,"'","' regex not allowed in URL",Settings.URL.DenyRegex.Action)){
			action.Set(Settings.URL.DenyRegex.Action);
		}
	}
	
	return action;
}

Action CHTTPFirewall::ScanURLDoS(CString& Url)
{
	Action action;

	//URL - Request Limits
	if(Settings.URL.RequestsLimit.Action && Url!="/"){
		//add request to cache
		Statistics.URL_RequestsLimit.Add(Url);

		//block if number of requests exceeds certain treshold
		if(Statistics.URL_RequestsLimit.Count(Url)>Settings.URL.RequestsLimit.MaxCount){
			action.Set(Settings.URL.RequestsLimit.Action);
			Alert("Reached URL requests limit",Settings.URL.RequestsLimit.Action);
		}
	}

	return action;
}

Action CHTTPFirewall::ScanQuerystring(CString& QueryString, bool doScanParameters)
{
	Action action;
	int l(0);
	if((l = QueryString.GetLength())==0){
		return action;
	}else{
		logger.Append(QueryString.Left(9000));

		//QUERYSTRING: size
		if(Settings.QueryString.MaxLength.Action){
			if (l>Settings.QueryString.MaxLength.Value){
				action.Set(Settings.QueryString.MaxLength.Action);
				Alert("QueryString is too long!",Settings.QueryString.MaxLength.Action);
			}
		}

		//QUERYSTRING: Parameter pollution
		if(doScanParameters)
			action |= ScanParameters(QueryString,Settings.QueryString.Parameters,Settings.ApplicationParameters.Query,"querystring");

		//QUERYSTRING: variable size
		if(Settings.QueryString.MaxVariableLength.Action && Settings.QueryString.MaxVariableLength.Value>0 && QueryString.Find('=')!=-1){
			if(ScanVariableLength(QueryString,Settings.QueryString.MaxVariableLength.Value,'&','&')){
				action.Set(Settings.QueryString.MaxVariableLength.Action);
				Alert("Maximum variable length exceeded in querystring",Settings.QueryString.MaxVariableLength.Action);
			}
		}

		//QUERYSTRING: encoding abuse
		if(Settings.QueryString.EncodingExploits){

			if(DenySequences(QueryString,Settings.EncodingExploits.Keywords,"Encoding exploit in querystring '","'",Settings.QueryString.EncodingExploits)){
				action.Set(Settings.QueryString.EncodingExploits);
			}

			if(DenyRegex(QueryString,Settings.EncodingExploits.Regex,"Encoding exploit in querystring '","'",Settings.QueryString.EncodingExploits)){
				action.Set(Settings.QueryString.EncodingExploits);
			}
		}
		
		QueryString = CURL::Decode(QueryString);

		if(Settings.QueryString.EncodingExploits){

			//QUERYSTRING: Encoding Exploits (normalize twice, except for '+', and reject if change occurs)
			if(Settings.EncodingExploits.ScanDoubleEncoding){
				if(CanHexDecode(QueryString,false)){
					action.Set(Settings.QueryString.EncodingExploits);
					Alert("Encoding exploit in querystring (embedded encoding)",Settings.QueryString.EncodingExploits);
				}
			}

			//QUERYSTRING: Invalid UTF-8
			if(Settings.EncodingExploits.ScanInvalidUTF8){
				if(!CUnicode::IsValidUTF8(QueryString)){
					action.Set(Settings.QueryString.EncodingExploits);
					Alert("Encoding exploit in querystring (invalid UTF-8)",Settings.QueryString.EncodingExploits);
				}
			}		
		}

		//QUERYSTRING: Deny directory traversal (parent path)
		if(Settings.QueryString.DirectoryTraversal){
			if(ScanDirectoryTraversal(QueryString)){
				action.Set(Settings.QueryString.DirectoryTraversal);
				Alert("Directory traversal not allowed in querystring",Settings.QueryString.DirectoryTraversal);
			}
		}

		//QUERYSTRING: Deny high bit characters (shellcode)
		if(Settings.QueryString.HighBitShellcode){
			if(ScanHighBitShellCode(QueryString)){
				action.Set(Settings.QueryString.HighBitShellcode);
				Alert("High bit characters (shellcode) not allowed in querystring",Settings.QueryString.HighBitShellcode);
			}
		}

		//QUERYSTRING: Deny special whitespace characters
		if(Settings.QueryString.SpecialWhitespace){
			if(DenySpecialWhitespace(QueryString," not allowed in querystring",Settings.QueryString.SpecialWhitespace)){
				action.Set(Settings.QueryString.SpecialWhitespace);
			}
		}

		CStringHelper::Safe_MakeLower(QueryString);
		
		//QUERYSTRING: SQL injection (words in list should be lowercase)
		if(Settings.QueryString.SQLInjection){
			int sqlcount(0);
			CStringList Matches;
			sqlcount += ScanSQLInjection(QueryString,Settings.SQLi.Keywords,Matches,Settings.SQLi.NormalizeWhitespace,Settings.SQLi.ReplaceNumericWithOne);
			if(sqlcount>0){
				if(sqlcount>Settings.SQLi.AllowedCount){
					action.Set(Settings.QueryString.SQLInjection);
					Alert("Possible SQL injection in querystring (" + CStringHelper::ToString(Matches,",") + ")",Settings.QueryString.SQLInjection);
				}else{
					logger.Append("WARNING: SQL keyword found in querystring (" + CStringHelper::ToString(Matches,",") + "). " + CStringHelper::Safe_IntToAscii(Settings.SQLi.AllowedCount - sqlcount + 1) + " more will block request.");
				}
			}
		}

		//QUERYSTRING: deny certain sequences (list should be lowercase)
		if(Settings.QueryString.DenySequences.Action){
			if(DenySequences(QueryString,Settings.QueryString.DenySequences.List,"'","' not allowed in querystring",Settings.QueryString.DenySequences.Action)){
				action.Set(Settings.QueryString.DenySequences.Action);
			}
		}

		//QUERYSTRING: deny regex
		if(Settings.QueryString.DenyRegex.Action){
			if(DenyRegex(QueryString,Settings.QueryString.DenyRegex.Map,"'","' regex not allowed in querystring",Settings.QueryString.DenyRegex.Action)){
				action.Set(Settings.QueryString.DenyRegex.Action);
			}
		}

		return action;
	}
}

Action CHTTPFirewall::ScanConnection(CString &IP, bool& is_blacklisted, bool& is_monitored)
{
	Action action;

	//CONNECTION - IP blocking
	if(Settings.Connection.DenyAddresses.Enabled){
		if(Settings.IPRanges.Deny.IsInList(IP)){
			is_blacklisted = true;
			action.Set(Settings.Connection.DenyAddresses.Enabled);
			Alert("IP address '" + IP + "' not allowed",Settings.Connection.DenyAddresses.Enabled);
		}
	}

	//CONNECTION - Third party blocklists
	if(Settings.Connection.BlockLists.Action){
		POSITION pos = Settings.Connection.BlockLists.GetHeadPosition();
		CBlockList* b;
		while(pos!=NULL){
			b = (CBlockList*) Settings.Connection.BlockLists.GetNext(pos);
			if(b->ip.IsInList(IP)){
				action.Set(Settings.Connection.BlockLists.Action);
				Alert("IP address in blocklist '" + b->Name + "'",Settings.Connection.BlockLists.Action);
			}
		}
	}

	//CONNECTION - Request Limits
	if(Settings.Connection.RequestsLimit.Action){
		//add request to cache
		Statistics.IP_RequestsLimit.Add(IP);

		//block if number of requests exceeds certain treshold
		if(Statistics.IP_RequestsLimit.Count(IP)>Settings.Connection.RequestsLimit.MaxCount){
			action.Set(Settings.Connection.RequestsLimit.Action);
			Alert("Reached connection request limit",Settings.Connection.RequestsLimit.Action);
		}
	}

	//CONNECTION - Hacking IP Blocking (do not check for Settings.HTTPResponse.BlockIP.Enabled - see rule action)
	if(Statistics.IP_HACK_Blocked.Count(IP)>Settings.HTTPResponse.BlockIP.MaxCount){
		is_blacklisted = true;
		action.Set(true);/* Settings.HTTPResponse.BlockIP.Enabled can be false*/
		Alert("Blacklisted IP address (previous alert)",true /* Settings.HTTPResponse.BlockIP.Enabled can be false*/);
	}

	//RESPONSE MONITOR
	if(Settings.ResponseMonitor.ClientErrors.Action){
		if(Statistics.IP_RESPONSE_Client_Errors.Count(IP)>Settings.ResponseMonitor.ClientErrors.MaxCount){
			is_blacklisted = true;
			action.Set(Settings.ResponseMonitor.ClientErrors.Action);
			Alert("Blacklisted IP address (multiple HTTP client errors)",Settings.ResponseMonitor.ClientErrors.Action);
		}
	}
	if(Settings.ResponseMonitor.ServerErrors.Action){
		if(Statistics.IP_RESPONSE_Server_Errors.Count(IP)>Settings.ResponseMonitor.ServerErrors.MaxCount){
			is_blacklisted = true;
			action.Set(Settings.ResponseMonitor.ServerErrors.Action);
			Alert("Blacklisted IP address (multiple HTTP server errors)",Settings.ResponseMonitor.ServerErrors.Action);
		}
	}

	//CONNECTION - Hacking IP Monitoring (do not check for Settings.HTTPResponse.MonitorIP - see rule action)
	if(Statistics.IP_HACK_Monitored.Exists(IP)){
		is_monitored = true;
		logger.Append("MONITORED: IP address (previous alert)");
	}

	//CONNECTION - IP Monitoring
	if(Settings.Connection.MonitorAddresses.Enabled){
		if(Settings.IPRanges.Monitor.IsInList(IP)){
			is_monitored = true;
			logger.Append("MONITORED: IP address '" + IP + "'");
		}
	}

	return action;
}

Action CHTTPFirewall::ScanAuthentication(CString &User, CString &Pass, CString& IP)
{
	Action action;

	logger.Append(User);
	//logger.Append(Pass);	//too critical to log!

	//AUTH - block blank password
	if(Settings.Authentication.BlankPasswords && Pass==""){
		action.Set(Settings.Authentication.BlankPasswords);
		Alert("Blank passwords not allowed",Settings.Authentication.BlankPasswords);
	}
	//AUTH - block password=username
	if(Settings.Authentication.SamePasswordAsUsername && Pass.CompareNoCase(User)==0){
		action.Set(Settings.Authentication.SamePasswordAsUsername);
		Alert("Password is same as username",Settings.Authentication.SamePasswordAsUsername);
	}
	//AUTH - block default password lists
	if(Settings.Authentication.DenyDefaultPasswords.Action){
		if(Settings.Authentication.DenyDefaultPasswords.List.Find(Pass)!=NULL){
			action.Set(Settings.Authentication.DenyDefaultPasswords.Action);
			Alert("Default password '" + Pass + "' not allowed",Settings.Authentication.DenyDefaultPasswords.Action);
		}
	}

	//AUTH - Scan Account
	action |= ScanAccount(User);

	CStringHelper::Safe_MakeUpper(User);
		
	//AUTH - scan for DoS on authentication of accounts (lookup)
	if(Settings.Authentication.BruteForceAttack.Action){
		CString ipuser; ipuser=IP+User;
		//add this ip to cache
		if(Statistics.IP_Authentication.Count(ipuser,Pass)==0){
			Statistics.IP_Authentication.Add(ipuser,Pass);
		}
		//count ip references in cache
		if(Statistics.IP_Authentication.Count(ipuser)>Settings.Authentication.BruteForceAttack.MaxCount){
			action.Set(Settings.Authentication.BruteForceAttack.Action);
			Alert("Possible brute force attack or DoS.",Settings.Authentication.BruteForceAttack.Action);
		}
	}

	return action;
}

Action CHTTPFirewall::ScanFormsAuthentication(CString& Data, CString& IP)
{
	Action action;
	CFormsAuthenticationScan form;
	form.isPHP = Settings.Engine.IsPHP;
	form.removeLeadingSpace = true;

	form.Scan(Data,Settings.Authentication.UsernameFields,Settings.Authentication.PasswordFields);

	if(Settings.Authentication.FormParameterPollution){
		if(form.IsUsernamePolluted){
			action.Set(Settings.Authentication.FormParameterPollution);
			Alert("Username parameter pollution",Settings.Authentication.FormParameterPollution);
		}
		if(form.IsPasswordPolluted){
			action.Set(Settings.Authentication.FormParameterPollution);
			Alert("Password parameter pollution",Settings.Authentication.FormParameterPollution);
		}
	}

	if(form.User!="" && form.HasPass){
		logger.Append("Forms Authentication");
		action |= ScanAuthentication(form.User,form.Pass,IP);
	}

	return action;
}

Action CHTTPFirewall::ScanVerb(CString Verb, CString& ContentLength, CString& ContentType, CString& TransferEncoding)
{
	Action action;
	logger.Append(Verb.Left(2048));

	//VERB: only allow certain verbs (verbs in list are case sensitive!)
	if(Settings.Verbs.AllowVerbs.Action){
		if(!IsInList(Verb,Settings.Verbs.AllowVerbs.List)){
			action.Set(Settings.Verbs.AllowVerbs.Action);
			Alert("HTTP VERB not allowed",Settings.Verbs.AllowVerbs.Action);
		}
	}
	
	//VERB: Deny certain verbs (verbs in list should be uppercase)
	CStringHelper::Safe_MakeUpper(Verb); //Also deny lowercase & variants!
	if(Settings.Verbs.DenyVerbs.Action){
		if(IsInList(Verb,Settings.Verbs.DenyVerbs.List)){
			action.Set(Settings.Verbs.DenyVerbs.Action);
			Alert("HTTP VERB not allowed",Settings.Verbs.DenyVerbs.Action);
		}
	}

	/*
		RFC 2616 - GET/HEAD payload is allowed, but has no semantic meaning (is ignored), url is used for caching/proxy
		If you are changing the response based on the payload, you are violating the HTTP/1.1 spec

		RFC 7230 - payload is allowed for general HTTP request parsing.
			A user agent SHOULD NOT send a
		   Content-Length header field when the request message does not contain
		   a payload body and the method semantics do not anticipate such a
		   body.

		RFC 7231 - A payload within a GET request message has no defined semantics;
		   sending a payload body on a GET request might cause some existing
		   implementations to reject the request.
	*/
	if(Settings.Verbs.DenyPayload.Action){
		CString header("");
		if (ContentType.GetLength()>0)
			header="Content-Type";
		else if (ContentLength.GetLength()>0 && ContentLength!="0")
			header="Content-Length";
		else if (TransferEncoding.GetLength()>0)
			header = "Transfer-Encoding";
		if(header.GetLength()>0 && IsInList(Verb,Settings.Verbs.DenyPayload.List)){
			action.Set(Settings.Verbs.DenyPayload.Action);
			Alert("Payload not allowed (" + header + " header not allowed for this method)",Settings.Verbs.DenyPayload.Action);
		}
	}

	if(Settings.Post.RFCCompliant){
		if(ContentType.GetLength()>0 && ContentLength.GetLength()==0 && TransferEncoding.GetLength()==0){
			action.Set(Settings.Post.RFCCompliant);
			Alert("Payload not RFC compliant (missing content-length or transfer-encoding)",Settings.Post.RFCCompliant);
		}
	}

	return action;
}

Action CHTTPFirewall::ScanRawURL(CURL &RawUrl, CString& IP)
{
	Action action;
	CString URLDecoded = CURL::Decode(RawUrl.Url);

	//URL: RFC compliant
	if(Settings.URL.RFCCompliantURL){
		if(!RawUrl.IsRFCCompliant()){
			logger.Append(RawUrl.RawUrl.Left(4096));
			action.Set(Settings.URL.RFCCompliantURL);
			Alert("URL is not RFC compliant",Settings.URL.RFCCompliantURL);
		}
	}

	//URL: HTTP RFC compliant
	if(Settings.URL.RFCCompliantHTTPURL){
		if(!RawUrl.IsHTTPCompliantUrl()){
			logger.Append(RawUrl.RawUrl.Left(4096));
			action.Set(Settings.URL.RFCCompliantHTTPURL);
			Alert("URL is not HTTP RFC compliant (HTTP URL cannot contain authentication)",Settings.URL.RFCCompliantHTTPURL);
		}

		if(RawUrl.Fragment.GetLength()>0){
			logger.Append(RawUrl.RawUrl.Left(4096));
			action.Set(Settings.URL.RFCCompliantHTTPURL);
			Alert("URL is not HTTP RFC compliant (URL cannot contain fragment)",Settings.URL.RFCCompliantHTTPURL);
		}
	}

	//URL
	logger.Append(RawUrl.Url.Left(4096));

	//URL Scanning (RAW)
	if(Settings.URL.UseRawScan){

		//URL: Check size
		if(Settings.URL.MaxLength.Action){
			if (RawUrl.Url.GetLength() > Settings.URL.MaxLength.Value){
				action.Set(Settings.URL.MaxLength.Action);
				Alert("URL is too long!",Settings.URL.MaxLength.Action);
			}
		}

		//URL: check for encoding abuse
		if(Settings.URL.EncodingExploits){

			if(DenySequences(RawUrl.Url,Settings.EncodingExploits.Keywords,"Encoding exploit in URL '","'",Settings.URL.EncodingExploits)){
				action.Set(Settings.URL.EncodingExploits);
			}
			if(DenyRegex(RawUrl.Url,Settings.EncodingExploits.Regex,"Encoding exploit in URL '","'",Settings.URL.EncodingExploits)){
				action.Set(Settings.URL.EncodingExploits);
			}

			//URL: Encoding Exploits (normalize twice, except for '+', and reject if change occurs)
			if(Settings.EncodingExploits.ScanDoubleEncoding && CanHexDecode(URLDecoded,false)){
				action.Set(Settings.URL.EncodingExploits);
				Alert("Encoding exploit in URL (embedded encoding)",Settings.URL.EncodingExploits);
			}

			//URL: Invalid UTF-8
			if(Settings.EncodingExploits.ScanInvalidUTF8){
				if(!CUnicode::IsValidUTF8(URLDecoded)){
					action.Set(Settings.URL.EncodingExploits);
					Alert("Encoding exploit in URL (invalid UTF-8)",Settings.URL.EncodingExploits);
				}
			}	
		}

		//URL: scan
		action |= ScanURL(URLDecoded);
		action |= ScanURLDoS(URLDecoded);
	}

	//FILENAME (RAW)
	if(Settings.Filename.UseRawScan){
		CFileName fn(URLDecoded);
		action |= ScanFilename(fn);

		if(Settings.Global.IsInstalledAsGlobalFilter){ //no OnUrlMap in ISA/TMG
			action |= ScanExtensionDoS(fn.ExtensionLCase,IP);
		}
	}

	//QUERYSTRING (RAW)
	if(Settings.QueryString.UseRawScan && RawUrl.Querystring!=""){
		action |= ScanQuerystring(RawUrl.Querystring,!RawUrl.StartsWith(Settings.Admin.Url));
	}

	return action;
}

Action CHTTPFirewall::ScanVersion(const CString &Version)
{
	Action action;
	logger.Append(Version.Left(1024));

	//VERSION: Check size
	if(Settings.HTTPVersion.MaxLength.Action){
		if (Version.GetLength() > Settings.HTTPVersion.MaxLength.Value){
			action.Set(Settings.HTTPVersion.MaxLength.Action);
			Alert("HTTP version too long",Settings.HTTPVersion.MaxLength.Action);
		}
	}
		
	//VERSION: allowed HTTP versions
	if(Settings.HTTPVersion.Allow.Action){
		if(!IsInList(Version,Settings.HTTPVersion.Allow.List)){
			action.Set(Settings.HTTPVersion.Allow.Action);
			Alert("HTTP version not in allowed list",Settings.HTTPVersion.Allow.Action);
		}
	}

	//denied http versions not needed
	
	return action;
}

Action CHTTPFirewall::ScanHost(const CString &Version, const CString& Host, const CString& IP)
{
	Action action;
	//logger.Append(Host.Left(1024));

	//VERSION: host header required for HTTP 1.1 (most likely worms/script kiddies/other stuff that is not RFC compliant)
	if(Settings.Host.RFCCompliant){
		if(Version=="HTTP/1.1" || Version=="HTTP/2.0"){
			if(Host==""){
				action.Set(Settings.Host.RFCCompliant);
				Alert("'Host:' header required for HTTP 1.1 request",Settings.Host.RFCCompliant);
			}
			/*
		}else{
			if((Version=="HTTP/0.9" || Version=="") && Host!=""){
				action.Set(Settings.Headers.RFCCompliantHostHeader);
				Alert("'Host:' header not allowed in HTTP 0.9",Settings.Headers.RFCCompliantHostHeader);
			}//*/
		}
	}

	//Host: Allowed (exact matches)
	if(Settings.Host.AllowHosts.Action){
		if(!IsInList(Host,Settings.Host.AllowHosts.List)){
			action.Set(Settings.Host.AllowHosts.Action);
			Alert("Host '" + Host.Left(1024) + "' not allowed",Settings.Host.AllowHosts.Action);
		}
	}

	//Host: Denied (match like IIS does)
	if(Settings.Host.DenyHosts.Action && Host.GetLength()>0){
		//IIS5: removes everything after :port
		//IIS7: Invalid Hostname if something after :port
		/*
			IIS7
									http://localhost:80 	http://127.0.0.1:80		http://[::1]:80
			Host: localhost			allowed					allowed					allowed
			Host: [::1]				invalid					invalid					allowed
			Host: 127.0.0.1			allowed					allowed					invalid
			Host: localhost[:80]/b	invalid					invalid					invalid

			IIS5 allows all
		*/
		bool ismatch = IsInListCompareNoCase(Host,Settings.Host.DenyHosts.List);
		if(!ismatch){
			int pos = Host.Find(':'); //remove port
			if(pos!=-1)
				ismatch = IsInListCompareNoCase(Host.Left(pos),Settings.Host.DenyHosts.List);

		}

		if(ismatch){
			//Host: Allow access from certain IP addresses to denied hosts
			if(!Settings.Host.AllowDenyHostsAccess.Enabled || !Settings.IPRanges.AllowDeniedHosts.IsInList(IP)){
				action.Set(Settings.Host.DenyHosts.Action);
				Alert("Host '" + Host.Left(1024) + "' not allowed",Settings.Host.DenyHosts.Action);
			}
		}
	}

	return action;
}

Action CHTTPFirewall::ScanCookie(CString &Cookie, CString& IP, CString& UA, CString& url)
{
	Action action;
	if(Cookie.GetLength()==0){
		return action;
	}else{

		logger.Append(Cookie.Left(9000));
		CStringList sessions;

		//COOKIE: Parameter pollution
		action |= ScanParameters(Cookie,Settings.Cookie.Parameters,Settings.ApplicationParameters.Cookie,"cookie",';','=',&sessions);

		//COOKIE: variable size
		if(Settings.Cookie.MaxVariableLength.Action && Settings.Cookie.MaxVariableLength.Value>0){
			if(ScanVariableLength(Cookie,Settings.Cookie.MaxVariableLength.Value,' ',' ')){
				action.Set(Settings.Cookie.MaxVariableLength.Action);
				Alert("Maximum variable length exceeded in cookie",Settings.Cookie.MaxVariableLength.Action);
			}
		}
	
		//COOKIE: check for encoding abuse
		if(Settings.Cookie.EncodingExploits){

			if(DenySequences(Cookie,Settings.EncodingExploits.Keywords,"Encoding exploit in cookie '","'",Settings.Cookie.EncodingExploits)){
				action.Set(Settings.Cookie.EncodingExploits);
			}
			if(DenyRegex(Cookie,Settings.EncodingExploits.Regex,"Encoding exploit in cookie '","'",Settings.Cookie.EncodingExploits)){
				action.Set(Settings.Cookie.EncodingExploits);
			}
		}

		Cookie = CURL::Decode(Cookie); //can be encoded: http://wp.netscape.com/newsref/std/cookie_spec.html

		if(Settings.Cookie.EncodingExploits){

			//COOKIE: Deny encoding exploits (normalize twice, except for '+', and reject if change occurs)
			if(Settings.EncodingExploits.ScanDoubleEncoding){
				if(CanHexDecode(Cookie,false)){
					action.Set(Settings.Cookie.EncodingExploits);
					Alert("Encoding exploit in cookie (embedded encoding)",Settings.Cookie.EncodingExploits);
				}
			}

			//COOKIE: Invalid UTF-8
			if(Settings.EncodingExploits.ScanInvalidUTF8){
				if(!CUnicode::IsValidUTF8(Cookie)){
					action.Set(Settings.Cookie.EncodingExploits);
					Alert("Encoding exploit in cookie (invalid UTF-8)",Settings.Cookie.EncodingExploits);
				}
			}
		}

		//COOKIE: Deny directory traversal (parent path)
		if(Settings.Cookie.DirectoryTraversal){
			if(ScanDirectoryTraversal(Cookie)){
				action.Set(Settings.Cookie.DirectoryTraversal);
				Alert("Directory traversal not allowed in cookie",Settings.Cookie.DirectoryTraversal);
			}
		}

		//COOKIE: Deny high bit characters (shellcode)
		if(Settings.Cookie.HighBitShellcode){
			if(ScanHighBitShellCode(Cookie)){
				action.Set(Settings.Cookie.HighBitShellcode);
				Alert("High bit characters (shellcode) not allowed in cookie",Settings.Cookie.HighBitShellcode);
			}
		}

		//COOKIE: Deny special whitespace characters
		if(Settings.Cookie.SpecialWhitespace){
			if(DenySpecialWhitespace(Cookie," not allowed in cookie",Settings.Cookie.SpecialWhitespace)){
				action.Set(Settings.Cookie.SpecialWhitespace);
			}
		}

		CStringHelper::Safe_MakeLower(Cookie);

		//COOKIE: Session hijacking
		if(Settings.Experimental.Session.Lock){

			if(!Settings.Experimental.Session.Excluded.Enabled || !IsInList(url, Settings.Experimental.Session.Excluded.List)){

				CString unique("");
				if(Settings.Experimental.Session.ByIP)
					unique += IP;
				if(Settings.Experimental.Session.ByUserAgent)
					unique += UA;
				
				POSITION pos = sessions.GetHeadPosition();
				CString session;
				while(pos!=NULL){
					session = sessions.GetNext(pos);
					if(Statistics.Sessions.Exists(session)){
						if(!Statistics.Sessions.Exists(session,unique)){
							action.Set(Settings.Experimental.Session.Lock);
							Alert("Session hijacking detected",Settings.Experimental.Session.Lock);
						}else{
							Statistics.Sessions.Update(session,unique);
						}
					}else{
						//add to cache, this needs to be done here (and not in OnSendResponse)
						//to prevent session fixation as well
						Statistics.Sessions.Add(session, unique);
					}
				}
			}
		}

		//COOKIE: Deny SQL injection
		if(Settings.Cookie.SQLInjection){
			int sqlcount( Settings.SQLi.Keywords.Find(";")!=NULL?-1:0 );
			CStringList Matches;
			sqlcount += ScanSQLInjection(Cookie,Settings.SQLi.Keywords,Matches,Settings.SQLi.NormalizeWhitespace,Settings.SQLi.ReplaceNumericWithOne);
			if(sqlcount>0){
				if(sqlcount>Settings.SQLi.AllowedCount){
					action.Set(Settings.Cookie.SQLInjection);
					Alert("Possible SQL injection in cookie (" + CStringHelper::ToString(Matches,",") + ")",Settings.Cookie.SQLInjection);
				}else{
					logger.Append("WARNING: SQL keyword found in cookie (" + CStringHelper::ToString(Matches,",") + "). " + CStringHelper::Safe_IntToAscii(Settings.SQLi.AllowedCount - sqlcount + 1) + " more will block request.");
				}
			}			
		}

		//COOKIE: deny certain sequences (list should be lowercase)
		if(Settings.Cookie.DenySequences.Action){
			if(DenySequences(Cookie,Settings.Cookie.DenySequences.List,"'","' not allowed in cookie",Settings.Cookie.DenySequences.Action)){
				action.Set(Settings.Cookie.DenySequences.Action);
			}
		}

		return action;
	}
}

Action CHTTPFirewall::ScanPath(CFileName& fn)
{
	Action action;
	logger.Append(fn.FullPath.Left(9000));

	//FULLPATH
	if(Settings.Path.ParentPath){
		if(DenyString(fn.FullPath,"..","Parent Path attempt ('..')",Settings.Path.ParentPath)){
			action.Set(Settings.Path.ParentPath);
		}
	}

	if(Settings.Path.Escaping){
		if(DenyChar(fn.FullPath,'%',"Possible encoding exploit",Settings.Path.Escaping)){
			action.Set(Settings.Path.Escaping);
		}
	}

	if(Settings.Path.SpecialWhitespace){
		if(DenySpecialWhitespace(fn.FullPath," not allowed in path",Settings.Path.SpecialWhitespace)){
			action.Set(Settings.Path.SpecialWhitespace);
		}
	}

	if(Settings.Path.MultipleColons){
		if(DenyMultipleCharacters(fn.FullPath,':',"Multiple colons not allowed in path",Settings.Path.MultipleColons)){
			action.Set(Settings.Path.MultipleColons);
		}
	}

	if(Settings.Path.Characters.Action){
		char c;
		for(int i=0;i<Settings.Path.Characters.Value.GetLength();i++){
			c = Settings.Path.Characters.Value.GetAt(i);
			if(DenyChar(fn.FullPath,c,"'" + CString(c) + "' not allowed in path",Settings.Path.Characters.Action))
				action.Set(Settings.Path.Characters.Action);
		}
	}

	//PATH: Deny dot in path (!= full path)
	if(Settings.Path.Dot){
		if(DenyChar(fn.Path,'.',"'.' not allowed in path",Settings.Path.Dot)){
			action.Set(Settings.Path.Dot);
		}
	}
	
	//PATH: Only allow certain paths (I use full paths here, because when
	//      using path, virtual dirs don't work if they are set to c:\somedir
	//      instead of c:\somedir\											*/
	if(Settings.Path.AllowPaths.Action){ //(lowercase!)
		if(!IsStartInList(fn.FullPathLCase,Settings.Path.AllowPaths.List)){
			action.Set(Settings.Path.AllowPaths.Action);
			Alert("Not in allowed path list '" + fn.FullPath + "'",Settings.Path.AllowPaths.Action);
		}
	}

	//FILENAME
	action |= ScanFilename(fn);

	return action;
}

Action CHTTPFirewall::ScanExtensionDoS(CString& ExtensionLCase, CString& IP)
{
	Action action;
	//EXTENSION - Request Limits
	if(Settings.Extensions.RequestsLimit.Action && IsInList(ExtensionLCase,Settings.Extensions.LimitExtensions)){
		//add request to cache
		Statistics.Extension_RequestsLimit.Add(IP);

		//block if number of requests exceeds certain treshold
		if(Statistics.Extension_RequestsLimit.Count(IP)>Settings.Extensions.RequestsLimit.MaxCount){
			action.Set(Settings.Extensions.RequestsLimit.Action);
			Alert("Reached file extension requests limit",Settings.Extensions.RequestsLimit.Action);
		}
	}
	return action;
}

Action CHTTPFirewall::ScanUserAgent(CString &UserAgent, CString& IP)
{
	Action action;

	//User-Agent 		=	"User-Agent" ":" 1*( product | comment )
	//product 			=	token ["/" product-version ]
	//product-version 	=	token
	//comment 			=	"(" *( ctext | comment ) ")"
	//ctext 			=	<any TEXT excluding "(" and ")">
	//token 			=	1*<any CHAR except CTLs or tspecials>
	//tspecials 		=	"(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\" | <"> | "/" | "[" | "]" | "?" | "=" | "{" | "}" | SP | HT

	//multiple User-Agents (or any headers exception):
	//Multiple message-header fields with the same field-name MAY be present in a message
	//if and only if the entire field-value for that header field is defined as a comma-separated
	//list [i.e., #(values)]. It MUST be possible to combine the multiple header fields into
	//one "field-name: field-value" pair, without changing the semantics of the message, by
	//appending each subsequent field-value to the first, each separated by a comma.

	if(UserAgent.GetLength()==0){
		//UA: Deny empty
		if(Settings.UserAgent.Empty){
			action.Set(Settings.UserAgent.Empty);
			Alert("Empty User Agent not allowed",Settings.UserAgent.Empty);
		}
	}else{

		//UA: require certain characters ('/ -.')
		if(Settings.UserAgent.RequireCharacter.Action && Settings.UserAgent.RequireCharacter.Value.GetLength()>0){
			if(UserAgent.FindOneOf(Settings.UserAgent.RequireCharacter.Value)==-1){
				action.Set(Settings.UserAgent.RequireCharacter.Action);
				Alert("User Agent requires at least one of these characters: '" + Settings.UserAgent.RequireCharacter.Value + "'",Settings.UserAgent.RequireCharacter.Action);
			}
		}

		//UA: Deny User Agent not RFC compliant
		if(Settings.UserAgent.NonRFC){
			//remove comments
			CString UserAgentClean = RemoveRFCComments(UserAgent);
			//logger.Append(UserAgentClean);
			//scan for non-token chars
			//if(UserAgentClean.FindOneOf("()<>@,;:\\\"/[]?={} \t")!=-1){
			if(UserAgentClean.FindOneOf("()<>@;:\\\"[]?={}\t")!=-1){	//allow '/' + ' ' + ',' (multiple headers with same name)
				action.Set(Settings.UserAgent.NonRFC);
				Alert("User Agent not RFC compliant",Settings.UserAgent.NonRFC);
			}
		}

		//UA: Deny high bit characters (shellcode)
		if(Settings.UserAgent.HighBitShellcode){
			if(ScanHighBitShellCode(UserAgent)){
				action.Set(Settings.UserAgent.HighBitShellcode);
				Alert("High bit characters (shellcode) not allowed in User Agent",Settings.UserAgent.HighBitShellcode);
			}
		}

		//UA: Deny special whitespace characters
		if(Settings.UserAgent.SpecialWhitespace){
			if(DenySpecialWhitespace(UserAgent," not allowed in User Agent",Settings.UserAgent.SpecialWhitespace)){
				action.Set(Settings.UserAgent.SpecialWhitespace);
			}
		}

		//UA: Deny current date
		if(Settings.UserAgent.CurrentDate.Action){
			SyncCurrentDates(Settings.UserAgent.CurrentDate.List);
			if(DenySequences(UserAgent,Settings.UA.CurrentDates,"Current date '","' not allowed in User Agent",Settings.UserAgent.CurrentDate.Action)){
				action.Set(Settings.UserAgent.CurrentDate.Action);
			}
		}

		//UA: Deny switching User-Agent
		if(Settings.UserAgent.Switching.Action){
			//add to cache
			Statistics.IP_UserAgent.AddNotInCache(IP,UserAgent);

			//block if number of requests exceeds certain treshold
			if(Statistics.IP_UserAgent.Count(IP)>Settings.UserAgent.Switching.MaxCount){
				action.Set(Settings.UserAgent.Switching.Action);
				Alert("User Agent is switching too much on this IP address",Settings.UserAgent.Switching.Action);
			}
		}

		//UA: Denied User-Agents (case insensitive)
		if(Settings.UserAgent.DenyUserAgents.Action){
			if(IsInListCompareNoCase(UserAgent,Settings.UserAgent.DenyUserAgents.List)){
				action.Set(Settings.UserAgent.DenyUserAgents.Action);
				Alert("User Agent not allowed",Settings.UserAgent.DenyUserAgents.Action);
			}
		}

		CStringHelper::Safe_MakeLower(UserAgent);

		//UA: Deny SQL injection (words in list should be lowercase)
		if(Settings.UserAgent.SQLInjection){	
			int sqlcount((Settings.SQLi.Keywords.Find(";")!=NULL && UserAgent.Find(";")!=-1)?-1:0); //ignore ;
			CStringList Matches;
			sqlcount += ScanSQLInjection(UserAgent,Settings.SQLi.Keywords,Matches,Settings.SQLi.NormalizeWhitespace,Settings.SQLi.ReplaceNumericWithOne);
			if(sqlcount>0){
				if(sqlcount>Settings.SQLi.AllowedCount){
					action.Set(Settings.UserAgent.SQLInjection);
					Alert("Possible SQL injection in User Agent (" + CStringHelper::ToString(Matches,",") + ")",Settings.UserAgent.SQLInjection);
				}else{
					logger.Append("WARNING: SQL keyword found in User Agent (" + CStringHelper::ToString(Matches,",") + "). " + CStringHelper::Safe_IntToAscii(Settings.SQLi.AllowedCount - sqlcount + 1) + " more will block request.");
				}
			}
		}

		//UA: Denied User-Agent Sequences (list should be lowercase)
		if(Settings.UserAgent.DenySequences.Action){
			if(DenySequences(UserAgent,Settings.UserAgent.DenySequences.List,"'","' not allowed in User Agent",Settings.UserAgent.DenySequences.Action)){
				action.Set(Settings.UserAgent.DenySequences.Action);
			}
		}

	}

	return action;
}

Action CHTTPFirewall::ScanContent(CString &ContentType, CString &ContentLength)
{
	Action action;

	if(ContentType.GetLength()>0){
		logger.Append(ContentType.Left(128));

		//HEADERS: Allowed Content-Types (case sensitive)
		if(Settings.ContentType.Allow.Action){
			if(!IsNotEmptyStartInList(ContentType,Settings.ContentType.Allow.List)){ //use IsNotEmptyStartInList for backwards compatibility when older settings file loaded (upgrading removes empty line)
				action.Set(Settings.ContentType.Allow.Action);
				Alert("Content-Type not in allowed list",Settings.ContentType.Allow.Action);
			}
		}

		CStringHelper::Safe_MakeLower(ContentType);

		//HEADERS: Denied Content-Types (list should be lowercase)
		if(Settings.ContentType.Deny.Action && ContentType.GetLength()>0){
			if(IsStartInList(ContentType,Settings.ContentType.Deny.List)){
				action.Set(Settings.ContentType.Deny.Action);
				Alert("Content-Type not allowed",Settings.ContentType.Deny.Action);
			}
		}
	}

	if(ContentLength.GetLength()>0){
		bool hasContentTypeLength(false);
		logger.Append(ContentLength.Left(64));

		//HEADERS: Limit Content-Length per Content-Type
		if(Settings.ContentType.MaxLength.Action){
			CString key;
			CString val;
			POSITION pos = Settings.ContentType.MaxLength.Map.GetStartPosition();
			while(pos!=NULL){
				Settings.ContentType.MaxLength.Map.GetNextAssoc(pos,key,val);
				if(ContentType.Left(key.GetLength())==key){
					hasContentTypeLength = true;
					if(!IsLengthAllowed(ContentLength,val)){
						action.Set(Settings.ContentType.MaxLength.Action);
						Alert("Content-Length is too long (" + key + '>' + val + ")",Settings.ContentType.MaxLength.Action);
					}
				}
			}
		}

		//HEADERS: Check Content-Length value
		if(Settings.ContentType.MaxContentLength.Action && !hasContentTypeLength){
			if(!IsLengthAllowed(ContentLength,Settings.ContentType.MaxContentLength.Value)){
				action.Set(Settings.ContentType.MaxContentLength.Action);
				Alert("Content-Length is too long (>" + Settings.ContentType.MaxContentLength.Value + ")",Settings.ContentType.MaxContentLength.Action);
			}
		}
	}

	
	return action;
}

Action CHTTPFirewall::ScanTransferEncoding(CString &TransferEncoding)
{
	Action action;

	if(TransferEncoding.GetLength()>0){

		//Transfer-Encoding: chunked;q=1.0, gzip
		//Let's not parse these, just deny them.

		//HEADERS: Allowed Transfer-Encodings (list is case sensitive)
		if(Settings.TransferEncoding.Allow.Action){
			if(!IsInList(TransferEncoding,Settings.TransferEncoding.Allow.List)){
				action.Set(Settings.TransferEncoding.Allow.Action);
				Alert("Transfer-Encoding '" + TransferEncoding.Left(1024) + "' not allowed",Settings.TransferEncoding.Allow.Action);
			}
		}

		//HEADERS: Denied Transfer-Encodings (list should be lowercase)
		if(Settings.TransferEncoding.Deny.Action){
			CStringHelper::Safe_MakeLower(TransferEncoding);

			if(IsInList(TransferEncoding,Settings.TransferEncoding.Deny.List)){
				action.Set(Settings.TransferEncoding.Deny.Action);
				Alert("Transfer-Encoding '" + TransferEncoding.Left(1024) + "' not allowed",Settings.TransferEncoding.Deny.Action);
			}
		}
	}

	return action;
}

bool CHTTPFirewall::IsExcludedSite(CString &instance)
{
	if(Settings.Engine.ExcludedInstances.Enabled && IsInList(instance,Settings.Engine.ExcludedInstances.List)){
		logger.Append("Web site instance is excluded from scanning");
		return true;
	}
	return false;
}

bool CHTTPFirewall::IsExcludedHost(CString& Host)
{
	if(Settings.Host.Excluded.Enabled && IsInList(Host,Settings.Host.Excluded.List)){
		logger.Append("Web site host is excluded from scanning");
		return true;
	}
	return false;
}

bool CHTTPFirewall::IsExcludedIP(CString& IP)
{
	if(Settings.Connection.ExcludedAddresses.Enabled && Settings.IPRanges.Exclude.IsInList(IP)){
		logger.Append("IP address is excluded from scanning");
		return true;
	}
	return false;
}

bool CHTTPFirewall::IsExcludedURL(CString& url, CString& Querystring)
{
	if	(
			(Settings.URL.ExcludedURL.Enabled && IsStartInList(url,Settings.URL.ExcludedURL.List)) ||
			(Settings.QueryString.ExcludedQueryString.Enabled && IsInList(Querystring,Settings.QueryString.ExcludedQueryString.List))
		)
	{
		logger.Append(CString(url + '?' + Querystring).Left(2048));
		logger.Append("URL is excluded from scanning");
		return true;
	}
	return false;
}

bool CHTTPFirewall::IsExcludedReferrerURL(CString& rawUrl)
{
	if(Settings.Referrer.Excluded.Enabled && IsStartInList(rawUrl,Settings.Referrer.Excluded.List))
	{
		logger.Append(rawUrl.Left(2048));
		logger.Append("Referrer URL is excluded from scanning");
		return true;
	}
	return false;
}


bool CHTTPFirewall::IsExcludedUserAgent(CString& UserAgent)
{
	if(Settings.UserAgent.Excluded.Enabled && IsInList(UserAgent,Settings.UserAgent.Excluded.List)){
		logger.Append("User Agent is excluded from scanning");
		return true;
	}
	return false;
}

void CHTTPFirewall::LoadCache()
{
	CFirewall::LoadCache();

	//Status code
	Settings.HTTPResponse.SyncStatusCode();

	//Response Server header
	Settings.ResponseMonitor.SyncServerHeader(true); //for backwards compatibility (when using old settings file)
	Settings.ResponseMonitor.SyncServerHeader(); //update ServerHeader variable...

	//(re-)load IP Lists
	Settings.IPRanges.Monitor.Enumerate(Settings.Connection.MonitorAddresses.List);
	Settings.IPRanges.Deny.Enumerate(Settings.Connection.DenyAddresses.List);
	Settings.IPRanges.Exclude.Enumerate(Settings.Connection.ExcludedAddresses.List);
	Settings.IPRanges.Admin.Enumerate(Settings.Admin.FromIP);
	Settings.IPRanges.AllowDeniedHosts.Enumerate(Settings.Host.AllowDenyHostsAccess.List);

	//stringcaches
	Statistics.IP_Authentication.SetMaxAge(CTimeSpan(0,0,Settings.Authentication.BruteForceAttack.MaxTime>1?Settings.Authentication.BruteForceAttack.MaxTime:1,0));//in min.
	Statistics.IP_RequestsLimit.SetMaxAge(CTimeSpan(0,0,Settings.Connection.RequestsLimit.MaxTime>1?Settings.Connection.RequestsLimit.MaxTime:1,0));	//in min.

	Statistics.IP_HACK_Monitored.SetMaxAge(CTimeSpan(0,Settings.HTTPResponse.MonitorIPTimeout>1?Settings.HTTPResponse.MonitorIPTimeout:1,0,0));//in hours.
	Statistics.IP_HACK_Blocked.SetMaxAge(CTimeSpan(0,Settings.HTTPResponse.BlockIP.MaxTime>1?Settings.HTTPResponse.BlockIP.MaxTime:1,0,0));//in hours.

	Statistics.URL_RequestsLimit.SetMaxAge(CTimeSpan(0,0,0,Settings.URL.RequestsLimit.MaxTime>1?Settings.URL.RequestsLimit.MaxTime:1));	//in sec.
	Statistics.Extension_RequestsLimit.SetMaxAge(CTimeSpan(0,0,Settings.Extensions.RequestsLimit.MaxTime>1?Settings.Extensions.RequestsLimit.MaxTime:1,0));	//in min.
	Statistics.IP_UserAgent.SetMaxAge(CTimeSpan(0,0,Settings.UserAgent.Switching.MaxTime>1?Settings.UserAgent.Switching.MaxTime:1,0));	//in min.

	Statistics.IP_RESPONSE_Client_Errors.SetMaxAge(CTimeSpan(0,0,Settings.ResponseMonitor.ClientErrors.MaxTime>1?Settings.ResponseMonitor.ClientErrors.MaxTime:1,0));	//in min.
	Statistics.IP_RESPONSE_Server_Errors.SetMaxAge(CTimeSpan(0,0,Settings.ResponseMonitor.ServerErrors.MaxTime>1?Settings.ResponseMonitor.ServerErrors.MaxTime:1,0));	//in min.

	Statistics.Sessions.SetMaxAge(CTimeSpan(0,0,Settings.Experimental.Session.Timeout>1?Settings.Experimental.Session.Timeout:1,0)); //in min.

	Settings.ApplicationParameters.Init();
	Settings.Headers.Validation.Init();

	//UA - current date
	SyncCurrentDates(Settings.UserAgent.CurrentDate.List);
}

void CHTTPFirewall::ClearCache()
{
	CFirewall::ClearCache();
	Statistics.Clear();
	Settings.ApplicationParameters.Clear();
	Settings.Headers.Validation.Clear();
}

void CHTTPFirewall::SetLoggerFields()
{
	//set logger fields
	CStringList fields;
	fields.AddTail("Date");
	fields.AddTail("Time");
	fields.AddTail("Site Instance");
	fields.AddTail("Event");
	if(Settings.Logging.LogClientIP) fields.AddTail("Client IP");
	if(Settings.Logging.LogUserName) fields.AddTail("Username");
	if(Settings.HTTPLogging.Log_HTTP_VIA) fields.AddTail("Via header");
	if(Settings.HTTPLogging.Log_HTTP_X_FORWARDED_FOR) fields.AddTail("HTTP_X_FORWARDED_FOR");
	if(Settings.HTTPLogging.LogHostHeader) fields.AddTail("Host header");
	if(Settings.HTTPLogging.LogUserAgent) fields.AddTail("User agent");
	fields.AddTail("Additional info about request (event specific)");
	logger.SetHeaderFields(fields);
}

Action CHTTPFirewall::ScanRawReferrerURL(LPCTSTR ReferrerUrl,LPCTSTR RequestedURLDecoded, CString& HostHeader, CString& UA)
{
	CURL RefUrl(ReferrerUrl);
	CFileName fn(RequestedURLDecoded);
	return ScanRawReferrerURL(RefUrl,fn,HostHeader,UA);
}

Action CHTTPFirewall::ScanRawReferrerURL(CURL &ReferrerUrl, CFileName& RequestedFile, CString& HostHeader, CString& UA)
{
	Action action;

	//REFERER URL
	logger.Append(ReferrerUrl.RawUrl.Left(4096));
	CString URLDecoded = CURL::Decode(ReferrerUrl.RawUrl);

	if(Settings.Referrer.UseScan && ReferrerUrl.RawUrl.GetLength()>0){
		
		//REFERER URL: RFC compliant
		if(Settings.Referrer.RFCCompliantURL){
			if(!ReferrerUrl.IsRFCCompliant()){
				action.Set(Settings.Referrer.RFCCompliantURL);
				Alert("Referrer URL is not RFC compliant",Settings.Referrer.RFCCompliantURL);
			}
		}

		//REFERER URL: HTTP RFC compliant
		if(Settings.Referrer.RFCCompliantHTTPURL){
			if(!ReferrerUrl.IsHTTPCompliantUrl()){
				action.Set(Settings.Referrer.RFCCompliantHTTPURL);
				Alert("Referrer URL is not HTTP RFC compliant (HTTP URL cannot contain authentication)",Settings.Referrer.RFCCompliantHTTPURL);
			}

			if(ReferrerUrl.Fragment.GetLength()>0 && 
				//HACK: IE 11/12 sends fragment in Referer!!! only Location: header can contain fragment
				//Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko
				//Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240
				(UA.Find(" Edge/")==-1) && /* allow MSIE 12 and up */
				(UA.Find(" Trident/7.0;")==-1 && UA.Find("; rv:11.")==-1) /* allow MSIE 11 */
			){
				action.Set(Settings.Referrer.RFCCompliantHTTPURL);
				Alert("Referrer URL is not HTTP RFC compliant (Referrer URL cannot contain fragment)",Settings.Referrer.RFCCompliantHTTPURL);
			}
		}

		//REFERER URL: check for encoding abuse & exploits
		if(Settings.Referrer.EncodingExploits){

			//REFERER URL: check for encoding abuse
			if(DenySequences(ReferrerUrl.RawUrl,Settings.EncodingExploits.Keywords,"Encoding exploit in Referrer URL '","'",Settings.Referrer.EncodingExploits)){
				action.Set(Settings.Referrer.EncodingExploits);
			}
			if(DenyRegex(ReferrerUrl.RawUrl,Settings.EncodingExploits.Regex,"Encoding exploit in Referrer URL '","'",Settings.Referrer.EncodingExploits)){
				action.Set(Settings.Referrer.EncodingExploits);
			}

			//REFERER URL: Encoding Exploits (normalize twice, except for '+', and reject if change occurs)
			if(Settings.EncodingExploits.ScanDoubleEncoding && CanHexDecode(URLDecoded,false)){
				action.Set(Settings.Referrer.EncodingExploits);
				Alert("Encoding exploit in Referrer URL (embedded encoding)",Settings.Referrer.EncodingExploits);
			}

			//REFERER URL: Invalid UTF-8
			if(Settings.EncodingExploits.ScanInvalidUTF8){
				if(!CUnicode::IsValidUTF8(URLDecoded)){
					action.Set(Settings.Referrer.EncodingExploits);
					Alert("Encoding exploit in Referrer URL (invalid UTF-8)",Settings.Referrer.EncodingExploits);
				}
			}
		}

		//REFERER URL: Scan Url
		action |= ScanReferrerURL(URLDecoded);

		/*
		//FILENAME (RAW)
		if(Settings.UseFilenameRawScan){
			action |= ScanFilename(CFileName(URLDecoded));
		}

		//QUERYSTRING (RAW)
		if(Settings.UseQuerystringRawScan && ReferrerUrl.Querystring!=""){
			action |= ScanQuerystring(ReferrerUrl.Querystring);
		}//*/
	}

	//REFERER URL: Deny deep linking
	if(Settings.Referrer.HotLinking) //also scan blank referrers
		action |= ScanHotLinking(URLDecoded,RequestedFile,HostHeader);

	return action;
}

Action CHTTPFirewall::ScanReferrerURL(CString& ReferrerURL)
{
	Action action;

	//REFERER URL: Deny certain characters
	if(Settings.Referrer.Characters.Action){
		char c;
		for(int i=0;i<Settings.Referrer.Characters.Value.GetLength();i++){
			c = Settings.Referrer.Characters.Value.GetAt(i);
			if(DenyChar(ReferrerURL,c,"'" + CString(c) + "' not allowed in Referrer URL",Settings.Referrer.Characters.Action))
				action.Set(Settings.Referrer.Characters.Action);
		}
	}
	//REFERER URL: Deny bad relative url parsers (with // in path)
	if (Settings.Referrer.BadParser){
		if(CURL::IsBadUrlParser(ReferrerURL)){
			action.Set(Settings.Referrer.BadParser);
			Alert("Bad relative url parser in Referrer URL",Settings.Referrer.BadParser);
		}
	}

	//REFERER URL: Deny high bit characters (shellcode)
	if(Settings.Referrer.HighBitShellcode){
		if(ScanHighBitShellCode(ReferrerURL)){
			action.Set(Settings.Referrer.HighBitShellcode);
			Alert("High bit characters (shellcode) not allowed in Referrer URL",Settings.Referrer.HighBitShellcode);
		}
	}

	//REFERER URL: Deny special whitespace characters
	if(Settings.Referrer.SpecialWhitespace){
		if(DenySpecialWhitespace(ReferrerURL, " not allowed in Referrer URL",Settings.Referrer.SpecialWhitespace)){
			action.Set(Settings.Referrer.SpecialWhitespace);
		}
	}

	//REFERER URL: obvious fake referrers (exact string match!)
	if(Settings.Referrer.Deny.Action){
		if(IsInList(ReferrerURL,Settings.Referrer.Deny.List)){
			action.Set(Settings.Referrer.Deny.Action);
			Alert("Referrer not allowed",Settings.Referrer.Deny.Action);
		}
	}

	CStringHelper::Safe_MakeLower(ReferrerURL);

	//REFERER URL: Only allow certain characters as the start of a URL (list should be lowercase)
	if(Settings.Referrer.Allow.Action){
		if(!IsStartInList(ReferrerURL,Settings.Referrer.Allow.List)){
			action.Set(Settings.Referrer.Allow.Action);
			Alert("Referrer URL not in allowed list",Settings.Referrer.Allow.Action);
		}
	}

	//REFERER URL: Deny SQL injection
	if(Settings.Referrer.SQLInjection){
		int sqlcount(0);
		CStringList Matches;
		sqlcount += ScanSQLInjection(ReferrerURL,Settings.SQLi.Keywords,Matches,Settings.SQLi.NormalizeWhitespace,Settings.SQLi.ReplaceNumericWithOne);
		if(sqlcount>0){
			if(sqlcount>Settings.SQLi.AllowedCount){
				action.Set(Settings.Referrer.SQLInjection);
				Alert("Possible SQL injection in referrer URL (" + CStringHelper::ToString(Matches,",") + ")",Settings.Referrer.SQLInjection);
			}else{
				logger.Append("WARNING: SQL keyword found in referrer URL (" + CStringHelper::ToString(Matches,",") + "). " + CStringHelper::Safe_IntToAscii(Settings.SQLi.AllowedCount - sqlcount + 1) + " more will block request.");
			}
		}
	}

	//REFERER URL: Deny certain sequences (list should be lowercase)
	if(Settings.Referrer.DenySequences.Action){
		if(DenySequences(ReferrerURL,Settings.Referrer.DenySequences.List,"'","' not allowed in Referrer URL",Settings.Referrer.DenySequences.Action)){
			action.Set(Settings.Referrer.DenySequences.Action);
		}
	}

	return action;
}

Action CHTTPFirewall::ScanHotLinking(CString& ReferrerURL, CFileName& RequestedFile, CString& HostHeader)
{
	Action action;

	//is certain url or file extension?
	if(IsListItemInString(RequestedFile.FullPathLCase,Settings.Referrer.HotLinkingUrls) || IsInList(RequestedFile.ExtensionLCase,Settings.Referrer.HotLinkingFileExtensions)){
		CString RefDomain = CURL::FQDNNoEndDot(ReferrerURL,false);
		CStringHelper::Safe_MakeLower(RefDomain);
		if(ReferrerURL.GetLength()==0 || ReferrerURL=="about:blank"){
			//REFERRER: Blank header
			if(Settings.Referrer.HotLinkingBlankReferrer){
				//also blocks some proxy servers and browsers with certain security applications
				action.Set(Settings.Referrer.HotLinkingBlankReferrer);
				Alert("Hot linking with blank referrer not allowed",Settings.Referrer.HotLinkingBlankReferrer);
			}
		}else{
			if(Settings.Referrer.HotLinkingUseHostHeader && RefDomain.CompareNoCase(HostHeader)==0 || RefDomain.GetLength()==0){
				//allow: HostHeader == RefDomain or relative referrer
			}else{
				//REFERRER: No Host header
				if(Settings.Referrer.HotLinkingUseHostHeader && HostHeader.GetLength()==0){
					logger.Append("WARNING: Hot linking 'Host:' header missing!");
				}
				//REFERRER: Allowed domains (list should be lowercase)
				if(Settings.Referrer.HotLinkingAllowDomains.Action){
					if(!IsInList(RefDomain,Settings.Referrer.HotLinkingAllowDomains.List)){
						action.Set(Settings.Referrer.HotLinkingAllowDomains.Action);
						Alert("Hot linking domain not in allowed list",Settings.Referrer.HotLinkingAllowDomains.Action);
					}
				}
				//REFERRER: Denied domains (list should be lowercase)
				if(Settings.Referrer.HotLinkingDenyDomains.Action){
					if(IsInList(RefDomain,Settings.Referrer.HotLinkingDenyDomains.List)){
						action.Set(Settings.Referrer.HotLinkingDenyDomains.Action);
						Alert("Hot linking domain in denied list",Settings.Referrer.HotLinkingDenyDomains.Action);
					}
				}
			}
		}
	}

	return action;
}

Action CHTTPFirewall::ScanParameters(CString& Data, RuleParameters& Rules, WebParam& Parameters, CString Location, TCHAR TokenKey, TCHAR TokenValue, CStringList* pSessions)
{
	Action action;
	int length = Data.GetLength();
	if(length>0 && (Data.Find(TokenValue)>-1 || Data.Find(TokenKey)>-1)){
		CValidationScan scan;
		scan.isPHP = Settings.Engine.IsPHP;
		scan.removeLeadingSpace = TokenKey==';' || Settings.Engine.IsPHP;
		scan.scanPollution = Rules.Pollution>Action::Disabled;
		scan.pSessions = pSessions;

		if(Rules.NameRequireRegex.Action)		
			scan.nameValidator = Settings.regex_cache.Lookup(Rules.NameRequireRegex.Value);
		if(Rules.InputValidation)
			scan.inputValidation = &(Settings.ApplicationParameters);

		scan.Scan(Data,TokenKey,TokenValue,Parameters);

		if(scan.result.pollutedParameters.GetCount()>0){
			action.Set(Rules.Pollution);
			Alert("Parameter pollution in " + Location + " '" + CStringHelper::ToString(scan.result.pollutedParameters,",") + "'",Rules.Pollution);
		}
		if(scan.result.failedParameters.GetCount()>0){
			action.Set(Rules.InputValidation);
			Alert("Parameter validation failed in " + Location + " '" + CStringHelper::ToString(scan.result.failedParameters,",") + "'",Rules.InputValidation);
		}
		if(scan.result.badParameters.GetCount()>0){
			action.Set(Rules.NameRequireRegex.Action);
			Alert("Parameter name not valid in " + Location + " '" + CStringHelper::ToString(scan.result.badParameters,",") + "'",Rules.NameRequireRegex.Action);
		}
	}

	return action;
}

CString CHTTPFirewall::GetAlertResponse(bool SendMessageBody, bool SendHeaders)
{
	CString buf("");
	if(SendHeaders){
		buf += "HTTP/1.1 ";
		if(Settings.HTTPResponse.UseStatus){
			buf += Settings.HTTPResponse.Status;
		}else{
			buf += "404 Object Not Found";
		}
		if(!Settings.ResponseMonitor.RemoveServerHeader){
			buf += "\r\nServer: ";
			if(Settings.ResponseMonitor.ChangeServerHeader){
				buf += Settings.ResponseMonitor.ServerHeader;
			}else{
				buf += Settings.Admin.ServerHeader;
			}
		}
		_tzset();
		CString d = CTime::GetCurrentTime().FormatGmt("%a, %d %b %Y %H:%M:%S GMT");
		buf += "\r\nDate: " + d;
		buf += "\r\nContent-Type: text/html; charset=windows-1252";
		buf += "\r\nContent-Length: "; buf += CStringHelper::Safe_IntToAscii(Settings.HTTPResponse.Contents.GetLength());
		buf += "\r\nPragma: no-cache";
		buf += "\r\nCache-control: no-cache";
		buf += "\r\nExpires: " + d;
		buf += CRLFCRLF;
	}

	if(SendMessageBody){ //see e-mail: special feature request of Sanford Whiteman if HEAD request -> no message body
		buf += Settings.HTTPResponse.Contents;
	}

	return buf;
}

void CHTTPFirewall::HackResponseBlockOrMonitor(CString& IP)
{
	//block or monitor IP address
	if(Settings.HTTPResponse.MonitorIP){
		Statistics.IP_HACK_Monitored.AddNotInCache(IP);
	}
	if(Settings.HTTPResponse.BlockIP.Enabled){
		Statistics.IP_HACK_Blocked.Add(IP); //don't use AddNotInCache (need count of alerts)
	}
}

void CHTTPFirewall::Initialize(CString ProductName, LPCTSTR ProductFullName, LPCTSTR UserAgentsFile, CString ConfigurationPath, LPCTSTR LogSuffix)
{
	CString strinit; CString strinit2; CString strinit3;
	CString owner = CProcessHelper::GetCurrentUserName();

	if(owner!="" && CFileName::Exists(ConfigurationPath + "Upgrade." + owner + ".xml")){
		//OWNER - upgrade settings
		Settings.IsUpgradeInProgress = true;
		strinit = LoadSettingFile(ConfigurationPath,"Upgrade." + owner + ".xml");
		if(CFileName::DeleteFile(ConfigurationPath + "Upgrade." + owner + ".xml")){
			CFileName::DeleteFile(ConfigurationPath + ProductName + "." + owner + ".xml");
		}
		Settings.Upgrade();
		Settings.IsUpgradeInProgress = false;
		//save settings file after upgrade
		strinit2 = SaveDefaultSettingFile(ConfigurationPath,ProductName + "." + owner + ".xml");
	}else{
		if(owner!="" && CFileName::Exists(ConfigurationPath + ProductName + "." + owner + ".xml")){
			//OWNER - settings per application pool identity (IIS7 by default possible, IIS 6 possible if you use separate application pool + identity)
			strinit = LoadSettingFile(ConfigurationPath,ProductName + "." + owner + ".xml");
		}else{
			if(CFileName::Exists(ConfigurationPath + "Upgrade.xml")){
				Settings.IsUpgradeInProgress = true;
				//upgrade settings
				strinit = LoadSettingFile(ConfigurationPath,"Upgrade.xml");
				if(CFileName::DeleteFile(ConfigurationPath + "Upgrade.xml")){
					CFileName::DeleteFile(ConfigurationPath + ProductName + ".xml");
				}
				Settings.Upgrade();
				Settings.IsUpgradeInProgress = false;
			}else{
				//default settings files
				strinit = LoadSettingFile(ConfigurationPath,ProductName + ".xml",ProductName + ".ini","urlscan.ini");
			}
			//create a default settings file if it doesn't exist
			strinit2 = SaveDefaultSettingFile(ConfigurationPath,ProductName + ".xml");
		}
	}
	Settings.Patch(); //apply patches when there are any

	CString logdir;
#ifdef SYSTEM_LOG_BUILD
	CString windir = GetWindowsPath();
	logdir = windir + "\\System32\\LogFiles\\" + ProductName + "\\"; //for global filter
	#pragma message("***** This build will log under the LogFiles folder of your Windows NT installation! *****")
#else
	logdir = ConfigurationPath  + "LogFiles\\";				   //<dir of dll>\LogFiles
#endif
	strinit3 = InitializeLogger(logdir,ProductFullName,LogSuffix);

	Message("AQTRONIX " + ProductName + " loaded");

	if(logger.CurrentLog.GetLastError()!=""){
		CString logformat = logger.FilenameFormat;
		int i = 1;
		while(logger.CurrentLog.GetLastError()!="" && i<100){
			CString logformati = logformat;
			logformati.Replace(".log", ".(" + CStringHelper::Safe_IntToAscii(i) + ").log");
			logger.FilenameFormat = logformati;
			logger.NewEntryFlush("AQTRONIX " + ProductName + " loaded");
			i++;
		}
	}

	Message(strinit);

	if(strinit2!="")
		Message(strinit2);
	if(strinit3!="")
		Message(strinit3);


	//are we in logging only mode? if so, warning!
	WarnLogonlyMode();

	//Robots.xml
	Settings.ReadAgentsFile(ConfigurationPath + UserAgentsFile);

	//Headers.xml
	Settings.Headers.Validation.ReadFromFile(ConfigurationPath + "Headers.xml");

	//Parameters.xml
	if(owner!="" && CFileName::Exists(ConfigurationPath + "Parameters." + owner + ".xml")){
		Settings.ApplicationParameters.ReadFromFile(ConfigurationPath + "Parameters." + owner + ".xml");
	}else{
		Settings.ApplicationParameters.ReadFromFile(ConfigurationPath + "Parameters.xml");
	}

	LoadCache();

	CFileName fnLoaded = Settings.GetLoadedSettingsFileName();
	SaveRunningValues(fnLoaded.Path,fnLoaded.FileName);
}

CString CHTTPFirewall::BuildDashboard()
{
	CString body("");

	body += CWebAdmin::WarnNoScript();

	//Stats
	body += CWebAdmin::AddTitle("Messages");
	body += "<article>";
	body += "<div class=\"accordion\">\r\n";
	body += CWebAdmin::ToTable("Alerts",Settings.Statistics.Alerts);
	body += CWebAdmin::ToTable("Messages",Settings.Statistics.Messages);
	body += "</div>\r\n";
	body += "</article>\r\n";

	//show server time (local/GMT)
	body += CWebAdmin::AddTitle("Firewall");
	body += "<article>\r\n";
	body += "<table>\r\n";
	body += "<tbody>\r\n";
	body += CWebAdmin::AddRow("Local server time",CTime::GetCurrentTime().Format("%Y-%m-%d %H:%M:%S"));
	body += CWebAdmin::AddRow("GMT/UTC",CTime::GetCurrentTime().FormatGmt("%Y-%m-%d %H:%M:%S"));
	body += CWebAdmin::AddRow("Started (UTC)",Settings.Admin.Started.FormatGmt("%Y-%m-%d %H:%M:%S"));
	body += CWebAdmin::AddRow("Running as account", CHTML::Encode(CProcessHelper::GetCurrentUserName()));
	body += CWebAdmin::AddRow("In the process", CHTML::Encode(CProcessHelper::GetProcessPath()));
	CString sf = Settings.FileStamp.FileName;
	if(sf=="")
		body += CWebAdmin::AddRow("Settings","<font color=\"red\">Default settings loaded</font>. Make sure the account above has read access on the settings files.");
	else
		body += CWebAdmin::AddRow("Settings loaded from file", CHTML::Encode(sf) + ", Version: " + CStringHelper::Safe_DoubleToAscii(Settings.Version));

	//Web Application Parameters
	sf = Settings.ApplicationParameters.FileStamp.FileName;
	if(sf=="")
		body += CWebAdmin::AddRow("Web Application Parameters", "<a href=\"?Parameters=Dashboard\">Not Set</a>");
	else
		body += CWebAdmin::AddRow("Web Application Parameters", CHTML::Encode(sf)+ ", Version: " + CStringHelper::Safe_DoubleToAscii(Settings.ApplicationParameters.Version));

	//Robots
	sf = Settings.Agents.AgentList.FileStamp.FileName;
	if(sf==""){
		body += CWebAdmin::AddRow("Robots database","<a href=\"?Robots=Dashboard\">Not Set</a>");
	}else{
		CTime t = Settings.Agents.AgentList.FileStamp.Time;
		CString status = CHTML::Encode(sf) + ", Version: " + CStringHelper::Safe_DoubleToAscii(Settings.Agents.AgentList.Version) + ", Last updated:";
		if(t < CTime::GetCurrentTime() - CTimeSpan(30,0,0,0)){
			status += " <font color=\"red\">" + t.Format("%Y-%m-%d") + "</font>";
			if(Settings.Admin.AllowConfigChanges)
				status += " -&gt; <a href=\"default.asp?update=Robots\">Update</a>";
		}else{
			status += " <font color=\"green\">" + t.Format("%Y-%m-%d") + "</font>";
		}
		body += CWebAdmin::AddRow("Robots database",status);
	}

	//Headers
	if(Settings.Experimental.Headers.InputValidation){
		sf = Settings.Headers.Validation.FileStamp.FileName;
		if(sf==""){
			body += CWebAdmin::AddRow("Headers database","<a href=\"?Headers=Dashboard\">Not Set</a>");
		}else{
			CTime t = Settings.Headers.Validation.FileStamp.Time;
			CString status = CHTML::Encode(sf) + ", Version: " + CStringHelper::Safe_DoubleToAscii(Settings.Headers.Validation.Version) + ", Last updated:";
			if(t < CTime::GetCurrentTime() - CTimeSpan(30,0,0,0)){
				status += " <font color=\"red\">" + t.Format("%Y-%m-%d") + "</font>";
				if(Settings.Admin.AllowConfigChanges)
					status += " -&gt; <a href=\"default.asp?update=Headers\">Update</a>";
			}else{
				status += " <font color=\"green\">" + t.Format("%Y-%m-%d") + "</font>";
			}
			body += CWebAdmin::AddRow("Headers database",status);
		}
	}


	body += "<tr><td>Logging:</td><td>";
	if(Settings.Logging.Enabled){
		if(logger.CurrentLog.GetLastError()!=""){
			body += " <font color=\"red\">";
			body += CHTML::Encode(logger.CurrentLog.GetLastError());
			body += "</font>";
		}else{
			body += CHTML::Encode(logger.CurrentLog.GetFileName());
		}
	}else{
		body += "disabled";
	}
	body += "</td></tr>\r\n";
	body += "</tbody>\r\n";
	body += "</table>\r\n";

	//admin access
	body += CWebAdmin::AddParagraph("This page is only accessible from these IP ranges:");
	body += "<div class=\"accordion\">\r\n";
	body += CWebAdmin::ToTable("Admin",Settings.IPRanges.Admin);
	body += "</div>\r\n";
	body += "</article>\r\n";

	return body;
}

CString CHTTPFirewall::BuildStatistics()
{
	CString body("");

	body += CWebAdmin::WarnNoScript();

	//Stats
	body += CWebAdmin::AddTitle("Statistics");
	body += "<article>\r\n";

	//Stringcaches
	body += "<div class=\"accordion\">\r\n";
	body += CWebAdmin::ToTable("IP - Authentication",Statistics.IP_Authentication, false);
	body += CWebAdmin::ToTable("IP - Requests Limit",Statistics.IP_RequestsLimit);
	body += CWebAdmin::ToTable("IP - Hack Monitored",Statistics.IP_HACK_Monitored);
	body += CWebAdmin::ToTable("IP - Hack Blocked",Statistics.IP_HACK_Blocked);
	body += CWebAdmin::ToTable("IP - Client Errors",Statistics.IP_RESPONSE_Client_Errors);
	body += CWebAdmin::ToTable("IP - Server Errors",Statistics.IP_RESPONSE_Server_Errors);
	body += CWebAdmin::ToTable("IP - User Agent",Statistics.IP_UserAgent);
	body += CWebAdmin::ToTable("URL - Requests Limit",Statistics.URL_RequestsLimit);
	body += CWebAdmin::ToTable("Extension - Requests Limit",Statistics.Extension_RequestsLimit);
	if(Settings.Experimental.Session.Lock)
		body += CWebAdmin::ToTable("Sessions",Statistics.Sessions);
	if(Settings.Experimental.UserAgent.UA.Count()>0)
		body += CWebAdmin::ToTable("New User Agents",Settings.Experimental.UserAgent.UA);
	body += GetStatisticsAdditionalCaches();
	body += "</div>\r\n";
	body += "</article>\r\n";

	//Regex patterns
	body += CWebAdmin::AddTitle("Regex Patterns");
	body += "<article>\r\n";
	body += "<div class=\"accordion\">\r\n";
	body += CWebAdmin::ToTable("Compiled Signatures",Settings.regex_cache,"Pattern","Status");
	body += "</div>\r\n";
	body += "</article>\r\n";

	return body;
}

CString CHTTPFirewall::BuildIPRanges()
{
	CString body("");
	body += CWebAdmin::WarnNoScript();

	//Stats
	body += CWebAdmin::AddTitle("IP Ranges");
	body += "<article>\r\n";

	//Parsed IP ranges
	body += "<div class=\"accordion\">\r\n";
	if(Settings.Connection.MonitorAddresses.Enabled)
		body += CWebAdmin::ToTable("Monitored",Settings.IPRanges.Monitor);
	if(Settings.Connection.DenyAddresses.Enabled)
		body += CWebAdmin::ToTable("Denied",Settings.IPRanges.Deny);
	if(Settings.Connection.ExcludedAddresses.Enabled)
		body += CWebAdmin::ToTable("Excluded",Settings.IPRanges.Exclude);
	if(Settings.Host.AllowDenyHostsAccess.Enabled)
		body += CWebAdmin::ToTable("Allow Denied Host Access",Settings.IPRanges.AllowDeniedHosts);

	//Blocklists
	if(Settings.Connection.BlockLists.Action>0){
		POSITION pos = Settings.Connection.BlockLists.GetHeadPosition();
		CBlockList* b;
		while(pos!=NULL){
			b = (CBlockList*) Settings.Connection.BlockLists.GetNext(pos);
			body += CWebAdmin::ToTable(CHTML::Encode(b->Name),b->ip);
		}
	}
	body += "</div>\r\n";
	body += "</article>\r\n";

	return body;
}

CString CHTTPFirewall::GetStatisticsAdditionalCaches()
{
	return "";
}

void CHTTPFirewall::SyncCurrentDates(CStringList& Formats)
{
	if(this->UpdateStamp.Time != Settings.UA.LastUpdated){ //only update every 1 minute (sync with settings refresh)
		Settings.UA.LastUpdated = this->UpdateStamp.Time;
		Settings.UA.CurrentDates.RemoveAll();
		POSITION pos = Formats.GetHeadPosition();
		while(pos!=NULL){
			Settings.UA.CurrentDates.AddTail(Settings.UA.LastUpdated.Format(Formats.GetNext(pos)));
		}
	}
}

void CHTTPFirewall::DebugLog(LPCTSTR Field1, LPCTSTR Field2, LPCTSTR Field3, LPCTSTR FilenameFormat, bool Escape)
{
	CLogger log;
	log.FilenameFormat = FilenameFormat;
	log.SetRetention(0);
	log.SetLogDir("C:\\Debug\\");
	log.NewEntry(Field1);
	log.Append(Field2);
	if(Escape)
		log.AppendEscape(CString(Field3));
	else
		log.Append(Field3);
	log.Flush();
}
