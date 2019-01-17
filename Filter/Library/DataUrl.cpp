/*
    AQTRONIX C++ Library
    Copyright 2018 Parcifal Aertssen

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
#include "stdafx.h"
#include "DataUrl.h"

#include "Url.h"
#include "Base64.h"
#include "StringHelper.h"

CDataUrl::CDataUrl(void)
{
}

CDataUrl::CDataUrl(LPCTSTR url)
{
	Parse(CString(url));
}

CDataUrl::CDataUrl(CString& url)
{
	Parse(url);
}

CDataUrl::~CDataUrl(void)
{
}

void CDataUrl::Parse(CString url)
{
	//https://tools.ietf.org/html/rfc2397

	ContentType = _T("");
	Entity = _T("");
	int posstart = url.Find(':');
	if(posstart>-1){
		CString scheme = url.Left(posstart);
		scheme.TrimLeft();
		CStringHelper::Safe_MakeLower(scheme);
		int posend = url.Find(',');
		if(scheme == _T("data") && posend>-1){
			ContentType = url.Mid(posstart+1,posend-posstart-1);
			ContentType.TrimLeft();
			if(ContentType.GetLength()==0)
				ContentType = _T("text/plain;charset=US-ASCII");
			if(ContentType.Find(_T("base64"))>-1)
				Entity = CBase64::Decode(url.Mid(posend+1));
			else
				Entity = CURL::Decode(url.Mid(posend+1));
		}
	}
}

CString CDataUrl::ToString(void)
{
	CString url(_T("data:"));
	url += ContentType;
	url += _T(",");
	if(ContentType.Find(_T("base64"))>-1)
		url += CBase64::Encode(Entity);
	else
		url += CURL::Encode(Entity);

	return url;
}

void CDataUrl::Extract(CString& text, CStringList& urls)
{
	int posstart = -1;
	int possep;
	int posend;
	int pos;
	posstart = text.Find("data:");
	TCHAR separators[] = {'\r','\n','\t',' ','\"','\'','<','>','(',')'};
	int length = 10;
	while(posstart>-1){
		possep = text.Find(',',posstart);
		if(possep>-1){
			posend = text.GetLength();
			for(int i=0; i<length; i++){
				pos = text.Find(separators[i],possep);
				if(pos>-1 && pos<posend)
					posend = pos;
			}
			if(posend>-1){
				urls.AddTail(text.Mid(posstart,posend-posstart));
			}
		}
		posstart = text.Find("data:",posstart+4);
	}
}

