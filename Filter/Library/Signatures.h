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
#pragma once

class CSignatures
{
public:
	static void JavaScript(CStringList& list);
	static void VBScript(CStringList& list);
	static void HTTPVersions(CStringList& List);
	static void AuthAccounts(CStringList& List);
	static void AuthPasswords(CStringList& List);
	static void EncodingExploits(CStringList& List);
	static void EncodingExploits(CMapStringToString& Map);
	static void SQLInjection(CStringList& List);
	static void UnixCommands(CStringList& List);
	static void MaliciousHTML(CStringList& List);
	static void ColdFusionExploits(CStringList& List);
	static void PHPExploits(CStringList& List);
	static void RemoteFileInclusion(CStringList& List);
	static void PaymentCards(CMapStringToString& Map);
	static void ErrorPages(CStringList& List);
	static void ErrorPages(CMapStringToString& Map);

	static CString RegexPatternCommandLine(CString command, CString parameter);
	static CString RegexPatternHtmlWhitespace();
	static CString RegexPatternHtmlAttribute(CString attribute, CString value);
	static CString RegexPatternHtmlAttribute(CString attribute);
	static CString RegexPatternHtmlEncoded(CString text);
	static CString RegexPatternHexIgnoreCase(CString text);
	static CString RegexPatternHttpHeader(CString header, CString value);
	static CString RegexPatternHttpHeaderOrder(CString header1, CString header2);

	CSignatures(void);
	virtual ~CSignatures(void);
};
