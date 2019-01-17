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
// StringHelper.h: interface for the CStringHelper class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_STRINGHELPER_H__B7D91791_D7D7_4790_BE42_0B931E82613B__INCLUDED_)
#define AFX_STRINGHELPER_H__B7D91791_D7D7_4790_BE42_0B931E82613B__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CStringHelper  
{
public:
	CStringHelper();
	virtual ~CStringHelper();

public:
	static CString Repeat(CString text, int times);
	static bool IsNumeric(CString& strAscii);
	static bool IsHex(CString& strHex);

	static CString Safe_DoubleToAscii(const double d);
	static CString Safe_DWORDToAscii(const DWORD dw);
	static CString Safe_LongToAscii(const long l);
	static CString Safe_IntToAscii(const int i);
	static float Safe_AsciiToFloat(CString& strAscii, float InvalidDefault = 0.0f);
	static int Safe_AsciiToInt(CString& strAscii, int InvalidDefault = 0, int OverflowDefault = INT_MAX);
	static unsigned char Safe_AsciiToUChar(CString& strAscii, unsigned char InvalidDefault = 0, unsigned char OverflowDefault = UCHAR_MAX);
	static int Safe_HexToInt(CString strHex, int InvalidDefault = 0, int OverflowDefault = INT_MAX);
	static unsigned char Safe_HexToUChar(CString strHex, unsigned char InvalidDefault = 0, unsigned char OverflowDefault = UCHAR_MAX);

	static CString ToString(CMapStringToString& Map, LPCTSTR LineSeparator = _T("\r\n"), LPCTSTR FieldSeparator = _T(":"));
	static CString ToString(CStringList& List);
	static CString ToString(CStringList& List, LPCTSTR Separator);
	static CString ToString(CStringArray& List);
	static CString ToString(CStringArray& List, LPCTSTR Separator);
	static void Copy(const CMapStringToString &MapIn, CMapStringToString& MapOut, bool ClearFirst = true);
	static void UCase(const CMapStringToString &MapIn, CMapStringToString& MapOut);
	static void LCase(const CMapStringToString &MapIn, CMapStringToString& MapOut);
	static CString ConvertBinaryData(BYTE* Data, DWORD Length, TCHAR ReplaceNullsWith);
	static bool ConvertBinaryData(BYTE* Data, DWORD Length, CString& Converted);
	static void AddNotInListUCase(CStringList& List, const CStringList& AppendList);
	static void AddNotInListLCase(CStringList& List, const CStringList& AppendList);
	static void AddNotInList(CStringList& List, const CStringList& AppendList);
	static void AddNotInList(CStringList& List, LPCTSTR Value);
	static void AddNotInMap(CMapStringToString &Map, LPCTSTR Key, LPCTSTR Value);

	static void RemoveFrom(CStringList& List, LPCTSTR Value);
	static void ReplaceKeyword(CStringList& List, LPCTSTR Item, LPCTSTR Replacement);
	static void ReplaceKeyword(CMapStringToString& map, LPCTSTR key, LPCTSTR find, LPCTSTR replacement);
	static void ReplaceKeyword(CMapStringToString& map, LPCTSTR find, LPCTSTR replacement);

	static void Split(LPCTSTR p, int Length, CStringList& List);
	static void Split(CStringList& list, CString Fields, CString Separator, UINT Max = 0);
	static void Split(CStringList& list, TCHAR separator, CMapStringToString& destination);

	static void LCase(CStringList& ListIn, CStringList& ListOut, bool ClearAll = true);
	static void LCase(CStringList& List);
	static void UCase(CStringList& ListIn, CStringList& ListOut, bool ClearAll = true);
	static void UCase(CStringList& List);
	static void LCase(CString& String);
	static void UCase(CString& String);
	static void Trim(CStringList& List);
	static CString& Trim(CString& String);
	static CString& Trim(CString& String, TCHAR c);
	static CString TrimCopy(CString String);

	static bool IsNotEmptyStartInList(const CString &Item, const CStringList &List);
	static bool IsStartInListCompareNoCase(const CString& Item, const CStringList& List);
	static bool IsStartInList(const CString& Item, const CStringList& List);
	static bool IsListItemInStringCompareNoCase(const CString& String, const CStringList& List);
	static bool IsListItemInString(const CString& String, const CStringList& List);
	static bool IsListItemInString(const CString& String1, const CString& String2, const CStringList& List);
	static bool IsInListItem(const CString& FindString, const CStringList& List);
	static bool IsInListCompareNoCase(const CString& Item, const CStringList& List);
	static bool IsInList(const CString& Item, const CStringList& List);
	static bool IsInList(const CString& Item, const CStringArray& List);
	static int CountKeywords(const CString& ScanString, const CStringList& Keywords, CStringList& Matches);
	static int CountKeywords(const CString& ScanString1, const CString& ScanString2, const CStringList& Keywords, CStringList& Matches);

	static void Safe_MakeLower(CString& CasedString);
	static void Safe_MakeUpper(CString& CasedString);
	static CString DetectEOL(CString Text);
	static void MakeWinEOL(CString& Text);
};

#endif // !defined(AFX_STRINGHELPER_H__B7D91791_D7D7_4790_BE42_0B931E82613B__INCLUDED_)
