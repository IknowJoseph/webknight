/*
    AQTRONIX C++ Library
    Copyright 2005-2016 Parcifal Aertssen

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
// XML.cpp: implementation of the CXML class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "XML.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/* CHANGELOG
 *	2018.01.23 Added Declaration()
 *  2016.12.11 Added support for decoding &#entity_number;
 *  2015.07.05 Added AttributeValue() and TagName() (was XMLKeyParameter() of Settings class)
 *  2005.08.26 Class created
 */

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CXML::CXML()
{
}

CXML::~CXML()
{
}

CString CXML::Encode(LPCTSTR str)
{
	CString enc(str);
	enc.Replace(_T("&"),_T("&amp;"));

	enc.Replace(_T("<"),_T("&lt;"));
	enc.Replace(_T(">"),_T("&gt;"));
	enc.Replace(_T("'"),_T("&apos;"));
	enc.Replace(_T("\""),_T("&quot;"));

	return enc;

	//https://alexatnet.com/articles/reference-undefined-entity-error-xml-file
	/*
	CString ret("");
	//encode ascii > 127
	unsigned char c;
	char bufint[34] = "\0";
	for(int i=0; i<enc.GetLength(); i++){
		c = enc.GetAt(i);
		if(c>127){
			CString entity = "&#";
			entity += _itoa(c,bufint,10);
			entity += ";";
			ret += entity;
		}else{
			ret += c;
		}
	}

	return ret;
	*/
}

CString CXML::Decode(LPCTSTR str)
{
	CString enc(str);

	//decode ascii > 127
	if(enc.Find("&#")>-1){
		char bufint[34] = "\0";
		for(unsigned char c=255; c>127; c--){
			CString entity = "&#";
			_itoa(c,bufint,10);
			entity += bufint;
			entity+= ";";
			CString r("");
			r += c;
			enc.Replace(entity,r);
		}
		//hex
		if(enc.Find("&#x")>-1){
			for(unsigned char c=255; c>127; c--){
				CString entity = "&#x";
				_itoa(c,bufint,16);
				entity += bufint;
				entity+= ";";
				CString r("");
				r += c;
				enc.Replace(entity,r);
			}
		}
	}

	enc.Replace(_T("&lt;"),_T("<"));
	enc.Replace(_T("&gt;"),_T(">"));
	enc.Replace(_T("&apos;"),_T("'"));
	enc.Replace(_T("&quot;"),_T("\""));

	enc.Replace(_T("&amp;"),_T("&"));
	return enc;
}

CString CXML::AttributeValue(CString tag, CString par)
{
	int pos = tag.Find(par + "=");
	if(pos!=-1){
		CString ret;
		ret = tag.Mid(pos+par.GetLength()+1);
		CString sep(ret.Left(1));
		if(sep=='\'' || sep=='"'){
			ret = ret.Mid(1);
		}else{
			sep = " ";
		}
		pos = ret.Find(sep);
		if(pos!=-1){
			return ret.Left(pos);
		}
	}
	return "";
}

CString CXML::TagName(CString tag)
{
	int pos;
	CString ret(tag);
	pos = tag.Find(' ');
	if(pos!=-1){
		ret = tag.Left(pos);
	}
	ret.TrimLeft('<');
	ret.TrimLeft('/');
	ret.TrimRight('>');
	ret.TrimRight('/');
	return ret;
}

CString CXML::Declaration()
{
	CString ret;
	ret  = _T("<?xml version=\"1.0\" encoding=\"windows-1252\" standalone=\"yes\"?>\r\n");	//xml declaration
	ret += _T("<?xml-stylesheet type=\"text/xsl\" href=\"GUI.xsl\"?>\r\n"); //GUI XSLT
	return ret;
}
