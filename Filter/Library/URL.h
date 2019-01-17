/*
    AQTRONIX C++ Library
    Copyright 2003-2006 Parcifal Aertssen

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
// URL.h: interface for the CURL class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_URL_H__7639661B_F026_4B18_A3C8_B86166A276B5__INCLUDED_)
#define AFX_URL_H__7639661B_F026_4B18_A3C8_B86166A276B5__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CURL  
{
public:
	bool StartsWith(CString& path);
	CString GetDomain();
	static CString FQDN(CString URL);
	static CString FQDNNoEndDot(CString URL, bool removePort = true);
	bool IsHTTPCompliantUrl();
	CString GetFragment();
	CString GetQuerystring();
	CString GetUrl();
	bool SetUrl(CString& URL);
	static bool IsValidScheme(CString& scheme);
	bool IsRFCCompliant();
	static bool IsUrlSafe(CString& urlEncodedText);
	static bool IsBadUrlParser(CString url);

	static CString Encode(CString text);
	static CString Decode(CString text);
	static CString URLEncodedToASCII(const char* str, bool convert_all = true, bool replace_null = true);
	static inline int HexToInt(const char char1, const char char2);
	static inline int HexToInt(const char* hex);
	
	CURL(CString strUrl = "");
	virtual ~CURL();

	CString RawUrl;
	CString Url;
	CString Querystring;
	CString Fragment;
	CString Domain;
	CString Scheme;

protected:
	inline void DeleteContents();
	bool IsRFC1808Compliant();
	bool IsRFC1738Compliant();
};

#endif // !defined(AFX_URL_H__7639661B_F026_4B18_A3C8_B86166A276B5__INCLUDED_)
