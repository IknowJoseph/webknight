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
// StringHelper.cpp: implementation of the CStringHelper class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "StringHelper.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/* CHANGELOG
 *  2015.07.22 Added Trim(CString&, TCHAR)
 *  2013.11.17 Added ReplaceKeyword()
 *  2013.05.13 Added AddNotInMap()
 *  2013.04.14 Added Safe_HexToUChar(), Safe_HexToInt(), IsHex() for IPv6 parsing
 *  2006.06.26 Added Safe_IntToAscii(), Safe_DWORDToAscii()
 *	2005.07.18 Class created
 */
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CStringHelper::CStringHelper()
{

}

CStringHelper::~CStringHelper()
{

}

void CStringHelper::AddNotInMap(CMapStringToString &Map, LPCTSTR Key, LPCTSTR Value)
{
	LPCTSTR rKey;
	if(!Map.LookupKey(Key,rKey))
		Map.SetAt(Key,Value);
}

void CStringHelper::AddNotInList(CStringList &List, LPCTSTR Value)
{
	if(List.Find(Value)==NULL)
		List.AddTail(Value);
}

void CStringHelper::AddNotInList(CStringList &List, const CStringList &AppendList)
{
	POSITION pos;
	pos = AppendList.GetHeadPosition();
	while(pos!=NULL){
		const CString& Value = (const CString&) AppendList.GetNext(pos);
		if(List.Find(Value)==NULL)
			List.AddTail(Value);
	}
}

void CStringHelper::AddNotInListLCase(CStringList &List, const CStringList &AppendList)
{
	POSITION pos;
	CString Value("");
	pos = AppendList.GetHeadPosition();
	while(pos!=NULL){
		Value = AppendList.GetNext(pos);
		Safe_MakeLower(Value);
		if(List.Find(Value)==NULL)
			List.AddTail(Value);
	}
}

void CStringHelper::AddNotInListUCase(CStringList &List, const CStringList &AppendList)
{
	POSITION pos;
	CString Value("");
	pos = AppendList.GetHeadPosition();
	while(pos!=NULL){
		Value = AppendList.GetNext(pos);
		Safe_MakeUpper(Value);
		if(List.Find(Value)==NULL)
			List.AddTail(Value);
	}
}

void CStringHelper::RemoveFrom(CStringList &List, LPCTSTR Value)
{
	POSITION pos = List.Find(Value);
	if(pos!=NULL)
		List.RemoveAt(pos);
}

void CStringHelper::ReplaceKeyword(CStringList& List, LPCTSTR Item, LPCTSTR Replacement)
{
	POSITION pos = List.Find(Item);
	if(pos!=NULL){
		List.SetAt(pos,Replacement);
	}
}

void CStringHelper::ReplaceKeyword(CMapStringToString& map, LPCTSTR key, LPCTSTR find, LPCTSTR replacement)
{
	CString value;
	if(map.Lookup(key,value)){
		value.Replace(find,replacement);
		map.SetAt(key,value);
	}
}

void CStringHelper::ReplaceKeyword(CMapStringToString& map, LPCTSTR find, LPCTSTR replacement)
{
	CString key;
	CString value;
	POSITION pos = map.GetStartPosition();
	while(pos!=NULL){
		map.GetNextAssoc(pos,key,value);
		value.Replace(find,replacement);
		map.SetAt(key,value);
	}
}

void CStringHelper::Split(LPCTSTR p, const int Length, CStringList& List)
{
	/* Removes everything from the list if length > 0
	 * and adds all entries from the string to the list
	 */
	if(Length>0){
		List.RemoveAll();	//remove everything
		List.AddTail(p);	//first entry
		for(int i=0;i+1<Length;i++){
			if (p[i]=='\0'){
				if(p[i+1]!='\0')
					List.AddTail(&p[i+1]);	//rest of it
			}
		}
	}
}

void CStringHelper::Split(CStringList& list, CString Fields, const CString Separator, UINT Max)
{
	if(Separator.GetLength()==0){	//if empty separator
		list.AddTail(Fields);
	}else{
		int pos1(0);
		int pos2(-1);
		UINT count(1);
		int lenSep(0); lenSep = Separator.GetLength();
		int length(0); length = Fields.GetLength();
		do{
			pos2 = Fields.Find(Separator,pos1);
			if(pos2==-1){
				pos2 = length;
			}
			list.AddTail(Fields.Mid(pos1,pos2-pos1));
			pos1 = pos2 + lenSep;
			count++;
		}while(pos1<length && (Max==0 || count<Max));
		
		if(count==Max){
			CString orphan;
			pos2 += lenSep;
			orphan = Fields.Mid(pos2,length-pos2);
			if(orphan!=""){
				list.AddTail(orphan);
			}
		}
	}
}

void CStringHelper::Split(CStringList& list, TCHAR separator, CMapStringToString& destination)
{
	POSITION pos = list.GetHeadPosition();
	CString val; int poseq; CString tmp;
	while (pos!=NULL){
		CString& str = list.GetNext(pos);
		poseq = str.Find(separator);
		if(poseq!=-1){
			if(str.Mid(poseq+1) != ""){
				tmp = str.Mid(0,poseq);
				destination.SetAt(tmp,str.Mid(poseq+1));
			}
		}
	}
}
void CStringHelper::LCase(CStringList& List)
{
	POSITION pos = List.GetHeadPosition();
	while(pos!=NULL){
		Safe_MakeLower(List.GetNext(pos));
	}
}

void CStringHelper::LCase(CStringList& ListIn, CStringList& ListOut, bool ClearAll)
{
	POSITION pos = ListIn.GetHeadPosition();
	CString Item;
	if(ClearAll)
		ListOut.RemoveAll();
	while(pos!=NULL){
		Item = ListIn.GetNext(pos);
		Safe_MakeLower(Item);
		ListOut.AddTail(Item);
	}
}

void CStringHelper::UCase(CStringList& List)
{
	POSITION pos = List.GetHeadPosition();
	while(pos!=NULL){
		Safe_MakeUpper(List.GetNext(pos));
	}
}

void CStringHelper::UCase(CStringList& ListIn, CStringList& ListOut, bool ClearAll)
{
	POSITION pos = ListIn.GetHeadPosition();
	CString Item;
	if(ClearAll)
		ListOut.RemoveAll();
	while(pos!=NULL){
		Item = ListIn.GetNext(pos);
		Safe_MakeUpper(Item);
		ListOut.AddTail(Item);
	}
}

void CStringHelper::LCase(CString& String)
{
	Safe_MakeLower(String);
}

void CStringHelper::UCase(CString& String)
{
	Safe_MakeUpper(String);
}

CString& CStringHelper::Trim(CString& String)
{
	String.TrimLeft();
	String.TrimRight();
	return String;
}

CString& CStringHelper::Trim(CString& String, TCHAR c)
{
	String.TrimLeft(c);
	String.TrimRight(c);
	return String;
}

CString CStringHelper::TrimCopy(CString String)
{
	String.TrimLeft();
	String.TrimRight();
	return String;
}

void CStringHelper::Trim(CStringList& List)
{
	POSITION pos = List.GetHeadPosition();
	while(pos!=NULL){
		CString& String = List.GetNext(pos);
		String.TrimLeft();
		String.TrimRight();
	}
}

bool CStringHelper::IsInList(const CString &Item, const CStringArray &List)
{
	INT_PTR count = List.GetSize();
	if(count>0){
		for(INT_PTR i=0; i<count; i++){
			if(Item==List[i]){
				return true;
			}
		}
	}
	return false;
}

bool CStringHelper::IsInList(const CString &Item, const CStringList &List)
{
	POSITION pos = List.GetHeadPosition();
	while (pos!=NULL){
		if(Item==List.GetNext(pos)){
			return true;
		}
	}
	return false;
}

bool CStringHelper::IsInListItem(const CString& FindString, const CStringList& List)
{
	POSITION pos = List.GetHeadPosition();
	while(pos!=NULL){
		if(List.GetNext(pos).Find(FindString)!=-1){
			return true;
		}
	}
	return false;
}

bool CStringHelper::IsListItemInString(const CString& String1, const CString& String2, const CStringList& List)
{
	/*
	 * return true if list item is in either String1 or String2
	 */
	CString seq;
	POSITION pos = List.GetHeadPosition();
	while (pos != NULL){
		seq = List.GetNext(pos);
		if(String1.Find(seq)!=-1 || String2.Find(seq)!=-1){
			return true;
		}
	}
	return false;
}

bool CStringHelper::IsInListCompareNoCase(const CString &Item, const CStringList &List)
{
	POSITION pos = List.GetHeadPosition();
	while (pos!=NULL){
		if(List.GetNext(pos).CompareNoCase(Item)==0){
			return true;
		}
	}
	return false;
}

bool CStringHelper::IsListItemInString(const CString &String, const CStringList &List)
{
	POSITION pos = List.GetHeadPosition();
	while (pos!=NULL){
		if(String.Find(List.GetNext(pos))!=-1){
			return true;
		}
	}
	return false;
}

bool CStringHelper::IsListItemInStringCompareNoCase(const CString &String, const CStringList &List)
{
	CString seq;
	CString StringLCase(String);
	Safe_MakeLower(StringLCase);
	
	POSITION pos = List.GetHeadPosition();
	while (pos!=NULL){
		seq = List.GetNext(pos);
		Safe_MakeLower(seq);
		if(StringLCase.Find(seq)!=-1){
			return true;
		}
	}
	return false;
}

bool CStringHelper::IsStartInList(const CString &Item, const CStringList &List)
{
	CString seq;
	POSITION pos = List.GetHeadPosition();
	while (pos!=NULL){
		seq = List.GetNext(pos);
		if(Item.Left(seq.GetLength())==seq){
			return true;
		}
	}
	return false;
}

bool CStringHelper::IsStartInListCompareNoCase(const CString &Item, const CStringList &List)
{
	CString seq;
	POSITION pos = List.GetHeadPosition();
	while (pos!=NULL){
		seq = List.GetNext(pos);
		if(seq.CompareNoCase(Item.Left(seq.GetLength()))==0){
			return true;
		}
	}
	return false;
}

bool CStringHelper::IsNotEmptyStartInList(const CString &Item, const CStringList &List)
{	
	CString seq;
	POSITION pos = List.GetHeadPosition();
	while (pos!=NULL){
		seq = List.GetNext(pos);
		if(Item.Left(seq.GetLength()>0?seq.GetLength():Item.GetLength())==seq){
			return true;
		}
	}
	return false;
}

int CStringHelper::CountKeywords(const CString &ScanString, const CStringList &Keywords, CStringList& Matches)
{
	int Count(0); CString word;
	POSITION pos = Keywords.GetHeadPosition();
	while(pos!=NULL){
		word = Keywords.GetNext(pos);
		if(ScanString.Find(word)!=-1){
			Count += 1;
			Matches.AddTail(word);
		}
	}
	return Count;
}

int CStringHelper::CountKeywords(const CString &ScanString1, const CString &ScanString2, const CStringList &Keywords, CStringList& Matches)
{
	CString seq;
	int Count(0);
	POSITION pos = Keywords.GetHeadPosition();
	while(pos!=NULL){
		seq = Keywords.GetNext(pos);
		if(ScanString1.Find(seq)!=-1 || ScanString2.Find(seq)!=-1){
			Count += 1;
			Matches.AddTail(seq);
		}
	}
	return Count;
}


CString CStringHelper::ConvertBinaryData(BYTE* Data, DWORD Length, TCHAR ReplaceNullsWith)
{
	if(Length>0){
		LPSTR lps = new char[Length + 1];
		if(lps==NULL){
			return "";
		}else{
			for(DWORD i=0;i<Length;i++){
				if(Data[i]=='\0'){
					lps[i]=ReplaceNullsWith;		//remove embedded nulls with replacement
				}else{
					lps[i]=Data[i];
				}
			}
			lps[Length] = '\0';	//null terminate it (if indata=inbuffer it is not terminated)
			CString resp = lps;
			delete[] lps;
			return resp;
		}
	}else{
		return "";
	}
}

bool CStringHelper::ConvertBinaryData(BYTE* Data, DWORD Length, CString& ConvertedString)
{
	if(Length>0){
		LPSTR lps = new char[Length + 1];
		if(lps==NULL){
			return false;
		}else{
			bool ret(true);
			for(DWORD i=0;i<Length;i++){
				if(Data[i]=='\0'){
					ret = false;
				}else{
					lps[i]=Data[i];
				}
			}
			if(ret){
				lps[Length] = '\0';	//null terminate it (if indata=inbuffer it is not terminated)
				ConvertedString = lps;
			}
			delete[] lps;
			return ret;
		}
	}else{
		return false;
	}
}

void CStringHelper::LCase(const CMapStringToString &MapIn, CMapStringToString &MapOut)
{
	POSITION pos = MapIn.GetStartPosition();
	CString key; CString val;
	MapOut.RemoveAll();
	while(pos!=NULL){
		MapIn.GetNextAssoc(pos,key,val);
		Safe_MakeLower(key);
		Safe_MakeLower(val);
		MapOut.SetAt(key,val);
	}
}

void CStringHelper::UCase(const CMapStringToString &MapIn, CMapStringToString& MapOut)
{
	POSITION pos = MapIn.GetStartPosition();
	CString key; CString val;
	MapOut.RemoveAll();
	while(pos!=NULL){
		MapIn.GetNextAssoc(pos,key,val);
		Safe_MakeUpper(key);
		Safe_MakeUpper(val);
		MapOut.SetAt(key,val);
	}
}

void CStringHelper::Copy(const CMapStringToString &MapIn, CMapStringToString& MapOut, bool ClearFirst)
{
	POSITION pos = MapIn.GetStartPosition();
	CString key; CString val;
	if(ClearFirst)
		MapOut.RemoveAll();
	while(pos!=NULL){
		MapIn.GetNextAssoc(pos,key,val);
		MapOut.SetAt(key,val);
	}
}

CString CStringHelper::ToString(CStringList &List, LPCTSTR Separator)
{
	CString ret(_T(""));
	POSITION pos = List.GetHeadPosition();
	while(pos!=NULL){
		ret += List.GetNext(pos);
		if(pos!=NULL){
			ret += Separator;
		}
	}
	return ret;
}

CString CStringHelper::ToString(CStringList &List)
{
	CString ret(_T(""));
	POSITION pos = List.GetHeadPosition();
	while(pos!=NULL){
		ret += List.GetNext(pos);
	}
	return ret;
}

CString CStringHelper::ToString(CStringArray &List, LPCTSTR Separator)
{
	CString ret(_T(""));
	INT_PTR count = List.GetSize();
	if(count>0){
		for(INT_PTR i=0; i<count; i++){
			ret += List[i];
			if(i+1<count){
				ret += Separator;
			}
		}
	}
	return ret;
}

CString CStringHelper::ToString(CStringArray &List)
{
	CString ret(_T(""));
	INT_PTR count = List.GetSize();
	if(count>0){
		for(INT_PTR i=0; i<count; i++){
			ret += List[i];
		}
	}
	return ret;
}

CString CStringHelper::ToString(CMapStringToString &Map, LPCTSTR LineSeparator, LPCTSTR FieldSeparator)
{
	CString ret(_T(""));
	POSITION pos = Map.GetStartPosition();
	CString key;
	CString value;
	while(pos!=NULL){
		Map.GetNextAssoc(pos,key,value);
		ret += key + FieldSeparator + value;
		if(pos!=NULL){
			ret += LineSeparator;
		}
	}
	return ret;
}

unsigned char CStringHelper::Safe_AsciiToUChar(CString& strAscii, unsigned char InvalidDefault, unsigned char OverflowDefault)
{
	if(strAscii.GetLength()>3){
		return OverflowDefault;
	}else{
		if(IsNumeric(strAscii)){
			int i = atoi((LPCTSTR)strAscii);
			if(i>UCHAR_MAX){
				return OverflowDefault;
			}else{
				return (unsigned char)i;
			}
		}else{
			return InvalidDefault;
		}
	}
}

float CStringHelper::Safe_AsciiToFloat(CString& strAscii, float InvalidDefault)
{
	try{
		return atof((LPCTSTR)strAscii);
	}catch(...){
		return InvalidDefault;
	}
}

int CStringHelper::Safe_AsciiToInt(CString& strAscii, int InvalidDefault, int OverflowDefault)
{
	//TODO: 10 char -> overflow + minus sign
	if(strAscii.GetLength()>9){
		return OverflowDefault;
	}else{
		if(IsNumeric(strAscii)){
			try{
				return atoi((LPCTSTR)strAscii);
			}catch(...){
				return OverflowDefault;
			}
		}else{
			return InvalidDefault;
		}
	}
}

int CStringHelper::Safe_HexToInt(CString strHex, int InvalidDefault, int OverflowDefault)
{
	//TODO: 10 char -> overflow + minus sign
	if(strHex.GetLength()>8){
		return OverflowDefault;
	}else{
		if(IsHex(strHex)){
			try{
				strHex = "0x" + strHex;
				return strtol((LPCTSTR)strHex,NULL,16);
			}catch(...){
				return OverflowDefault;
			}
		}else{
			return InvalidDefault;
		}
	}
}

unsigned char CStringHelper::Safe_HexToUChar(CString strHex, unsigned char InvalidDefault, unsigned char OverflowDefault)
{
	if(strHex.GetLength()>2){
		return OverflowDefault;
	}else{
		if(IsHex(strHex)){
			strHex = "0x" + strHex;
			int i = strtol((LPCTSTR)strHex,NULL,16);
			if(i>UCHAR_MAX){
				return OverflowDefault;
			}else{
				return (unsigned char)i;
			}
		}else{
			return InvalidDefault;
		}
	}
}

bool CStringHelper::IsNumeric(CString &strAscii)
{
	int length = strAscii.GetLength();
	TCHAR c;
	if(length>0){
		for(int i=0;i<length;i++){
			c = strAscii.GetAt(i);
			if(c<48 || c>57){
				return false;
			}
		}
	}else{
		return false;
	}
	return true;
}

bool CStringHelper::IsHex(CString &strHex)
{
	int length = strHex.GetLength();
	TCHAR c;
	if(length>0){
		for(int i=0;i<length;i++){
			c = strHex.GetAt(i);
			if( c<48 || (c>57 && !((c>64 && c<71) || (c>96 && c<103)) ) ){
				return false;
			}
		}
	}else{
		return false;
	}
	return true;
}

CString CStringHelper::Safe_IntToAscii(const int i)
{
	char buf[33] = "\0";
	_itoa(i,buf,10);
	return buf;
}

CString CStringHelper::Safe_DWORDToAscii(const DWORD dw)
{
	char buf[33] = "\0";
	ltoa(dw,buf,10);
	return buf;
}

CString CStringHelper::Safe_LongToAscii(const long l)
{
	char buf[33] = "\0";
	ltoa(l,buf,10);
	return buf;
}

CString CStringHelper::Safe_DoubleToAscii(const double d)
{
	char buf[33] = "\0";
	sprintf(buf,"%f",d);
	return buf;
}

void CStringHelper::Safe_MakeLower(CString & CasedString)
{
	//http://www.thescripts.com/forum/thread445888.html
	
		//VS 6.0 = MSC 1200
		//VS 2005 = MSC 1400
		//VS 2008 = MSC 1500
		#if _MSC_VER > 1200
			try{
			#ifdef _UNICODE
				CasedString.MakeLower();
			#elif _MBCS
				CasedString.MakeLower();
			#else
				//no unicode AND no mbcs
				//VC 6 uses _tcslwr and does not generate an error on Korean locale because _tcslwr -> _strlwr!!!
				int nLength = CasedString.GetLength();
				LPTSTR pszBuffer = CasedString.GetBuffer( nLength );
				_tcslwr(pszBuffer);
				CasedString.ReleaseBuffer();			
			#endif
			}catch(...){
				//do nothing
			}
		#else
			CasedString.MakeLower();	//generates the following error: 1113 (ERROR_NO_UNICODE_TRANSLATION)
										//on Korean locale if compiled with VS2005 because it uses
										//mbslwr_s instead of _strlwr even if _MBCS is NOT set!!!!!??
		#endif
}

void CStringHelper::Safe_MakeUpper(CString & CasedString)
{
		//VS 6.0 = MSC 1200
		//VS 2005 = MSC 1400
		//VS 2008 = MSC 1500
		#if _MSC_VER > 1200
			try{
			#ifdef _UNICODE
				CasedString.MakeUpper();
			#elif _MBCS
				CasedString.MakeUpper();
			#else
				//no unicode AND no mbcs
				//VC 6 uses _tcsupr and does not generate an error on Korean locale because _tcsupr -> _strupr!!!
				int nLength = CasedString.GetLength();
				LPTSTR pszBuffer = CasedString.GetBuffer( nLength );
				_tcsupr(pszBuffer);
				CasedString.ReleaseBuffer();
			#endif
			}catch(...){
				//do nothing
			}
		#else
			CasedString.MakeUpper();	//generates the following error: 1113 (ERROR_NO_UNICODE_TRANSLATION)
										//on Korean locale if compiled with VS2005 because it uses
										//mbslwr_s instead of _strlwr even if _MBCS is NOT set!!!!!??
		#endif
}

CString CStringHelper::Repeat(CString text, int times)
{
	CString ret(_T(""));
	for(int i=0; i<times; i++)
		ret += text;

	return ret;
}

CString CStringHelper::DetectEOL(CString Text)
{
	if(Text.Find(_T("\r\n"),0)!=-1) //DOS
		return _T("\r\n");

	if(Text.Find(_T("\n"),0)!=-1) //Unix
		return _T("\n");

	if(Text.Find(_T("\r"),0)!=-1) //Old Mac
		return _T("\r");

	return _T("\r\n"); //if no EOL separator found, use CRLF
}

void CStringHelper::MakeWinEOL(CString& text)
{
	text.Replace(_T("\r\n"),_T("\r"));
	text.Replace(_T("\n"),_T("\r"));
	text.Replace(_T("\r"),_T("\r\n"));
}