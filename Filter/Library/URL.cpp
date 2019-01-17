/*
    AQTRONIX C++ Library
    Copyright 2003-2013 Parcifal Aertssen

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
*/// URL.cpp: implementation of the CURL class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "URL.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/* CHANGELOG
 *	2018.01.27 Added StartsWith
 *  2016.12.28 Added IsBadUrlParser
 *  2016.04.05 Added IsUrlSafe
 *  2015.10.21 Added unsafe characters in IsRFCCompliant()
 *  2013.05.22 Added removePort parameter to FQDNNoEndDot()
 *  2010.12.26 Fixed bug in decode function: should ignore % sign if not valid hex (could be used to bypass SQL injection scanning)
 *  2007.07.08 Fixed unsigned char bug in URLEncodedToASCII() and HexToChar()->HexToInt() overload
 *  2006.04.18 Added GetDomain() function and improved FQDN function
 *             Remove minor bug in SetUrl(): checks if "//" is DIRECTLY after ':'
 *  2006.01.11 Added FQDN() functions
 *	2005.10.25 Code optimization int -> unsigned char
 *  2004.02.22 Fixed buffer overrun issue in URLEncodedToASCII() (new returns NULL)
 *	2004.02.01 Optimized code in IsRFCxxxxCompliant functions (check Scheme
 *             variable instead of extracting scheme from raw url)
 *             Added IsHTTPCompliantUrl()
 *	2004.01.26 Added DeleteContents() -> this fixed minor bug where scheme
 *             would not be cleared if SetUrl() was called more than once.
 *	2003.11.11 Improved code in SetUrl for parsing absolute urls (+ fixed bug
 *             where url with a '?' in login would be seen as querystring).
 *	2003.11.02 First version of this class finished
 */

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CURL::CURL(CString strUrl)
{
	if(strUrl!="")
		SetUrl(strUrl);
}

CURL::~CURL()
{

}


bool CURL::IsValidScheme(CString& str){

	/*
		Scheme names consist of a sequence of characters. The lower case
		letters "a"--"z", digits, and the characters plus ("+"), period
		("."), and hyphen ("-") are allowed. For resiliency, programs
		interpreting URLs should treat upper case letters as equivalent to
		lower case in scheme names (e.g., allow "HTTP" as well as "http").
	*/
	if (str=="")
		return false;

	for(int i=0;i<str.GetLength();i++){
		if(str[i]!='+' && str[i]!='.' && str[i]!='-' && (str[i]<65 || (str[i]>90 && str[i]<97) || str[i]> 122))
			return false;
	}
	return true;
}

bool CURL::IsRFCCompliant(){

	return (IsRFC1808Compliant() || IsRFC1738Compliant());
}

bool CURL::IsRFC1738Compliant(){

	/*
	 * RFC 1738 Uniform Resource Locators (URL)
	 */

	//valid scheme
	if(!IsValidScheme(Scheme)){
		return false;
	}

	//valid characters
	for(int i=0; i<RawUrl.GetLength();i++){
		//in printable US-ASCII
		if(RawUrl[i]<32 || RawUrl[i]>127)
			return false;
		
		if(	
			//punctuation
			RawUrl[i]==' ' || 
			RawUrl[i]=='<' || 
			RawUrl[i]=='>' || 
			RawUrl[i]=='"' ||

			//unsafe
			RawUrl[i]=='{' ||
			RawUrl[i]=='}' ||
			RawUrl[i]=='|' ||
			RawUrl[i]=='\\'||
			RawUrl[i]=='^' ||
			//RawUrl[i]=='~' || //allow for unix systems + allowed in RFC 2396
			//RawUrl[i]=='[' || //IPv6 literal
			//RawUrl[i]==']' || //IPv6 literal
			RawUrl[i]=='`'
		){
			return false;
		}
	}

	//Common Internet Scheme Syntax
	/*
		ip-schemepart  = "//" login [ "/" urlpath ]

		login          = [ user [ ":" password ] "@" ] hostport
		hostport       = host [ ":" port ]
		host           = hostname | hostnumber
		hostname       = *[ domainlabel "." ] toplabel
		domainlabel    = alphadigit | alphadigit *[ alphadigit | "-" ] alphadigit
		toplabel       = alpha | alpha *[ alphadigit | "-" ] alphadigit
		alphadigit     = alpha | digit
		hostnumber     = digits "." digits "." digits "." digits
		port           = digits
		user           = *[ uchar | ";" | "?" | "&" | "=" ]
		password       = *[ uchar | ";" | "?" | "&" | "=" ]
		urlpath        = *xchar    ; depends on protocol see section 3.1
	*/

	return true;
}

bool CURL::IsRFC1808Compliant(){

	/*
	 * RFC 1808 Relative Uniform Resource Locators
	 */

	if(IsValidScheme(Scheme)){
		return false;
	}

	//valid characters
	for(int i=0; i<RawUrl.GetLength();i++){
		//in printable US-ASCII
		if(RawUrl[i]<32 || RawUrl[i]>127)
			return false;
		
		if(	
			//punctuation
			RawUrl[i]==' ' || 
			RawUrl[i]=='<' || 
			RawUrl[i]=='>' || 
			RawUrl[i]=='"' ||

			//unsafe
			RawUrl[i]=='{' ||
			RawUrl[i]=='}' ||
			RawUrl[i]=='|' ||
			RawUrl[i]=='\\'||
			RawUrl[i]=='^' ||
			//RawUrl[i]=='~' || //allow for unix systems + allowed in RFC 2396
			//RawUrl[i]=='[' || //IPv6 literal
			//RawUrl[i]==']' || //IPv6 literal
			RawUrl[i]=='`'
		){
			return false;
		}
	}
	
	return true;
}

bool CURL::IsUrlSafe(CString& urlEncodedText){

	//URL Encoded data
	//according to RFC 1738 section 2.2

	//valid characters
	for(int i=0; i<urlEncodedText.GetLength();i++){
		//in printable US-ASCII
		if(urlEncodedText[i]<32 || urlEncodedText[i]>127)
			return false;
		
		if(	
			//punctuation
			urlEncodedText[i]==' ' || 
			urlEncodedText[i]=='<' || 
			urlEncodedText[i]=='>' || 
			urlEncodedText[i]=='"' ||

			//fragment
			urlEncodedText[i]=='#' ||

			//unsafe
			urlEncodedText[i]=='{' ||
			urlEncodedText[i]=='}' ||
			urlEncodedText[i]=='|' ||
			urlEncodedText[i]=='\\'||
			urlEncodedText[i]=='^' ||
			//urlEncodedText[i]=='~' || //allowed in RFC 2396
			urlEncodedText[i]=='[' ||
			urlEncodedText[i]==']' ||
			urlEncodedText[i]=='`'
		){
			return false;
		}
	}
	
	return true;
}

bool CURL::SetUrl(CString &URL)
{
	DeleteContents();

	//set raw url
	RawUrl = URL;

	//locate querystring and fragment position
	/*
		ip-schemepart  = "//" login [ "/" urlpath ]

		login          = [ user [ ":" password ] "@" ] hostport
		hostport       = host [ ":" port ]
		host           = hostname | hostnumber
		hostname       = *[ domainlabel "." ] toplabel
		domainlabel    = alphadigit | alphadigit *[ alphadigit | "-" ] alphadigit
		toplabel       = alpha | alpha *[ alphadigit | "-" ] alphadigit
		alphadigit     = alpha | digit
		hostnumber     = digits "." digits "." digits "." digits
		port           = digits
		user           = *[ uchar | ";" | "?" | "&" | "=" ]
		password       = *[ uchar | ";" | "?" | "&" | "=" ]
		urlpath        = *xchar    ; depends on protocol see section 3.1
	*/
	int posscheme;
	int pos2slash;
	int posquery; int PosQuery;
	int posslash; int PosSlash;
	int PosFragment;
	
	//scheme
	posscheme = RawUrl.Find(':');
	if(posscheme!=-1){
		Scheme = RawUrl.Left(posscheme);
		if(IsValidScheme(Scheme)){
			//find "//" after scheme
			if("//" == RawUrl.Mid(posscheme+1,2)){
				pos2slash = posscheme+2;
			}else{
				pos2slash = posscheme;
			}
		}else{
			pos2slash = 0;
		}
	}else{
		pos2slash = 0;
	}
	
	//find "/" if present
	posslash = PosSlash = RawUrl.Find('/',pos2slash);
	if(posslash==-1)
		posslash=pos2slash;
	
	//find querystring
	posquery = PosQuery = RawUrl.Find('?',posslash);
	if(posquery==-1)
		posquery=posslash;

	//find fragment
	PosFragment = RawUrl.Find('#',posquery);

	//parse URL
	if(PosFragment==-1){
		Fragment= "";
	}else{
		Fragment = URL.Right(URL.GetLength()-PosFragment-1);
	}
	if(PosQuery!=-1){
		Url = URL.Left(PosQuery);
		if(PosFragment==-1){
			Querystring = URL.Mid(PosQuery+1);
		}else{
			Querystring = URL.Mid(PosQuery+1,PosFragment-PosQuery-1);
		}
	}else{
		if(PosFragment==-1){
			Url = URL;
		}else{
			Url = URL.Left(PosFragment);
		}
	}

	//return
	return true;
}

CString CURL::GetUrl()
{
	return Url;
}

CString CURL::GetQuerystring()
{
	return Querystring;
}

CString CURL::GetFragment()
{
	return Fragment;
}

bool CURL::StartsWith(CString& path)
{
	return Url.GetLength()>=path.GetLength() && Url.Left(path.GetLength())==path;
}

CString CURL::Encode(CString text)
{
	//percent sign first
	text.Replace(_T("%"),_T("%25"));

	//reserved characters
	text.Replace(_T("!"),_T("%21"));
	text.Replace(_T("#"),_T("%23"));
	text.Replace(_T("$"),_T("%24"));
	text.Replace(_T("&"),_T("%26"));
	text.Replace(_T("'"),_T("%27"));
	text.Replace(_T("("),_T("%28"));
	text.Replace(_T(")"),_T("%29"));
	text.Replace(_T("*"),_T("%2A"));
	text.Replace(_T("+"),_T("%2B"));
	text.Replace(_T(","),_T("%2C"));
	text.Replace(_T("/"),_T("%2F"));
	text.Replace(_T(":"),_T("%3A"));
	text.Replace(_T(";"),_T("%3B"));
	text.Replace(_T("="),_T("%3D"));
	text.Replace(_T("?"),_T("%3F"));
	text.Replace(_T("@"),_T("%40"));
	text.Replace(_T("["),_T("%5B"));
	text.Replace(_T("]"),_T("%5D"));

	//additional characters
	text.Replace(_T(" "),_T("%20"));
	text.Replace(_T("\""),_T("%22"));
	text.Replace(_T("\r"),_T("%0D"));
	text.Replace(_T("\n"),_T("%0A"));
	text.Replace(_T("<"),_T("%3C"));
	text.Replace(_T(">"),_T("%3E"));

	return text;
}

CString CURL::Decode(CString text)
{
	//M$ unicode
	text.Replace(_T("%u00"),_T("%")); //ASCII in unicode format
	text.Replace(_T("%U00"),_T("%")); //ASCII in unicode format
	//hex encoding
	return URLEncodedToASCII(text);
}

CString CURL::URLEncodedToASCII(const char* str, bool convert_all, bool replace_null)
{
	/*
	 * Converts application/x-www-form-urlencoded data to ASCII
	 *
	 * Taken from: http://www.w3.org/TR/REC-html40/interact/forms.html#h-17.13.4
	 *
	 * Control names and values are escaped. Space characters are replaced by `+',
	 * and then reserved characters are escaped as described in [RFC1738],
	 * section 2.2: Non-alphanumeric characters are replaced by `%HH', a percent
	 * sign and two hexadecimal digits representing the ASCII code of the character.
	 * Line breaks are represented as "CR LF" pairs (i.e., `%0D%0A'). 
	 *
	 * The control names/values are listed in the order they appear in the document.
	 * The name is separated from the value by `=' and name/value pairs are separated
	 * from each other by `&'. 
	 */
	size_t length = strlen(str);
	if(length>0){
		char* p = new char[length + 1];
		if(p==NULL)
			return str;
		size_t i_p = 0;
		size_t i_str;
		//char ascii[3];
		int byte = -1;
		if (convert_all){
			for(i_str=0;i_str<length;i_str++,i_p++){
				switch (str[i_str]){
				case '%':					//escape character
					if(i_str+2<length){		//are there 2 characters after '%'?
						//ascii[0] = str[i_str+1];
						//ascii[1] = str[i_str+2];
						//ascii[2] = '\0';	//null terminate
						byte = HexToInt(str[i_str+1],str[i_str+2]);
						if(byte == -1){
							//p[i_p] = str[i_str];
							i_p--; //ignore %
						}else{
							if(replace_null && byte==0)
								byte = ' '; //replace %00 with space
							p[i_p] = byte;
							i_str += 2;			//skip 2 characters
						}
					}else{
						//p[i_p] = str[i_str];//just copy remaining chars if end of string
						i_p--; //ignore %
					}
					break;
				case '+':
					p[i_p] = ' ';
					break;
				default:
					p[i_p] = str[i_str];
					break;
				}
			}
		}else{
			for(i_str=0;i_str<length;i_str++,i_p++){
				switch (str[i_str]){
				case '%':					//escape character
					if(i_str+2<length){		//are there 2 characters after '%'?
						//ascii[0] = str[i_str+1];
						//ascii[1] = str[i_str+2];
						//ascii[2] = '\0';	//null terminate
						byte = HexToInt(str[i_str+1],str[i_str+2]);
						if(byte == -1){
							p[i_p] = str[i_str];
						}else{
							if(replace_null && byte==0)
								byte = ' '; //replace %00 with space
							p[i_p] = byte;
							i_str += 2;			//skip 2 characters
						}
					}else{
						p[i_p] = str[i_str];//just copy remaining chars if end of string
					}
					break;
				default:
					p[i_p] = str[i_str];
					break;
				}
			}
		
		}
		p[i_p] = '\0';	//null terminate
		CString tmp(p);
		delete[] p;
		return tmp;
	}else{
		return str;
	}
}

inline int CURL::HexToInt(const char *hex)
{
	/*
	 * Function converts string with hex value to integer (no overflow checking!)
	 * Returns -1 if it fails (else > 0)
	 */
	int val = 0;
	int digit = 0;
	for(unsigned char i=0;i<strlen(hex);i++){
		switch (hex[i]){
		case '0': digit = 0; break;
		case '1': digit = 1; break;
		case '2': digit = 2; break;
		case '3': digit = 3; break;
		case '4': digit = 4; break;
		case '5': digit = 5; break;
		case '6': digit = 6; break;
		case '7': digit = 7; break;
		case '8': digit = 8; break;
		case '9': digit = 9; break;
		case 'A': digit = 10; break;
		case 'B': digit = 11; break;
		case 'C': digit = 12; break;
		case 'D': digit = 13; break;
		case 'E': digit = 14; break;
		case 'F': digit = 15; break;
		case 'a': digit = 10; break;
		case 'b': digit = 11; break;
		case 'c': digit = 12; break;
		case 'd': digit = 13; break;
		case 'e': digit = 14; break;
		case 'f': digit = 15; break;
		default: return -1;
		}
		val *= 16;
		val += digit;
	}
	return val;
}

inline int CURL::HexToInt(const char char1, const char char2)
{
	/*
	 * Function converts numbers char1 and char2 to char (byte)
	 * Returns -1 if it fails (else > 0)
	 */
	unsigned char val = 0;
	unsigned char digit = 0;

	//char1
	switch (char1){
	case '0': digit = 0; break;
	case '1': digit = 1; break;
	case '2': digit = 2; break;
	case '3': digit = 3; break;
	case '4': digit = 4; break;
	case '5': digit = 5; break;
	case '6': digit = 6; break;
	case '7': digit = 7; break;
	case '8': digit = 8; break;
	case '9': digit = 9; break;
	case 'A': digit = 10; break;
	case 'B': digit = 11; break;
	case 'C': digit = 12; break;
	case 'D': digit = 13; break;
	case 'E': digit = 14; break;
	case 'F': digit = 15; break;
	case 'a': digit = 10; break;
	case 'b': digit = 11; break;
	case 'c': digit = 12; break;
	case 'd': digit = 13; break;
	case 'e': digit = 14; break;
	case 'f': digit = 15; break;
	default: return -1;
	}
	val = digit*16;

	//char2
	switch (char2){
	case '0': digit = 0; break;
	case '1': digit = 1; break;
	case '2': digit = 2; break;
	case '3': digit = 3; break;
	case '4': digit = 4; break;
	case '5': digit = 5; break;
	case '6': digit = 6; break;
	case '7': digit = 7; break;
	case '8': digit = 8; break;
	case '9': digit = 9; break;
	case 'A': digit = 10; break;
	case 'B': digit = 11; break;
	case 'C': digit = 12; break;
	case 'D': digit = 13; break;
	case 'E': digit = 14; break;
	case 'F': digit = 15; break;
	case 'a': digit = 10; break;
	case 'b': digit = 11; break;
	case 'c': digit = 12; break;
	case 'd': digit = 13; break;
	case 'e': digit = 14; break;
	case 'f': digit = 15; break;
	default: return -1;
	}
	val += digit;

	return val;
}

inline void CURL::DeleteContents()
{
	Fragment = "";
	Querystring = "";
	RawUrl = "";
	Scheme = "";
	Url = "";
	Domain = "";
}

bool CURL::IsHTTPCompliantUrl()
{
	if(Scheme.CompareNoCase(_T("http"))==0 || Scheme.CompareNoCase(_T("https"))==0){
		int posat = Url.Find('@');
		if(posat!=-1){
			int posslash = Url.Find('/',8);
			if((posat<posslash || posslash==-1)){
				return false;
			}
		}
	}
	return true;
}

CString CURL::FQDN(CString URL)
{
	CString Domain = FQDNNoEndDot(URL);
	if(Domain.Right(1)!=_T(".")){
		Domain += _T(".");
	}
	return Domain;
}

CString CURL::FQDNNoEndDot(CString URL, bool removePort)
{
	int posStart(0);
	int posEnd(0);
	int posscheme(0);
	int posAt(0);
	int posPort(0);

	//skip scheme
	posscheme = URL.Find(':');
	if(posscheme!=-1){
		if(URL.GetLength()<posscheme+4){
			return _T("");
		}else{
			//find "//" after scheme
			if(_T("//") == URL.Mid(posscheme+1,2)){
				posStart = posscheme+3;
			}else{
				posStart = posscheme+1;
			}
		}
	}
	
	//find end of domain
	posEnd = URL.Find('/',posStart);
	if(posEnd==-1){
		posEnd = URL.Find('?',posStart);
		if(posEnd==-1){
			posEnd = URL.Find('#',posStart);
			if(posEnd==-1){
				posEnd = URL.Find(';',posStart);
				if(posEnd==-1){
					posEnd = URL.Find('>',posStart); //urls may end with '>' in text
					if(posEnd==-1){
						posEnd = URL.Find('\"',posStart); //urls may end with '"' in text
						if(posEnd==-1){
							posEnd = URL.Find('\'',posStart); //urls may end with '"' in text

							//full length of string if not found
							if(posEnd==-1){
								posEnd = URL.GetLength();
							}
						}
					}
				}
			}
		}
	}

	//skip "username[:password]@" in url
	posAt = URL.Find('@',posStart);
	if(posAt!=-1 && posAt<posEnd){
		posStart = posAt+1;
	}

	//skip ":port"
	if(removePort){
		posPort = URL.Find(':',posStart);
		if(posPort!=-1 && posPort<posEnd){
			posEnd = posPort;
		}
	}
	if(posStart<posEnd){
		URL = URL.Mid(posStart,posEnd-posStart);
		if(URL.Right(1)==_T(".")){
			URL = URL.Left(URL.GetLength()-1);
		}
		return URL;
	}else{
		return _T("");
	}
}

CString CURL::GetDomain()
{
	if(Domain==""){
		Domain = FQDNNoEndDot(Url);
	}
	return Domain;
}

bool CURL::IsBadUrlParser(CString url)
{
	TCHAR c;
	int length = url.GetLength();
	for(int i=0; i<length-1; i++){
		c = url.GetAt(i);
		if(c==':')
			i++;
		else if(c=='/' && url.GetAt(i+1)=='/')
			return true;

		//skip query
		if(c=='?')
			return false;
		if(c==';')
			return false;
	}

	return false;
}