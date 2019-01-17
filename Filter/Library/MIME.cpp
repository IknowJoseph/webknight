/*
    AQTRONIX C++ Library
    Copyright 2016 Parcifal Aertssen

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
#include "MIME.h"
#include "StringHelper.h"

#define CRLF "\r\n"
#define CRLFCRLF "\r\n\r\n"

CMIME::CMIME(void)
{
	IsMultiPart = false;
	IsMultiPartFormData = false;
	IsUrlEncoded = false;
	IsUTF8Encoded = false;
	IsTextPlain = false;
	IsBinary = false;

	ContentType = "";
}

CMIME::CMIME(CString ContentType)
{
	IsMultiPart = false;
	IsMultiPartFormData = false;
	IsUrlEncoded = false;
	IsUTF8Encoded = false;
	IsText = false;
	IsTextPlain = false;
	IsBinary = false;

	Parse(ContentType);
}

CMIME::~CMIME(void)
{
}

void CMIME::Parse(CString ContentType)
{
	this->ContentType = ContentType;
	CStringHelper::Safe_MakeLower(this->ContentType);

	IsMultiPart = this->ContentType.Left(10)=="multipart/";
	if(IsMultiPart){
		Boundary = "";
		int posstart = this->ContentType.Find("boundary=");
		if(posstart>-1){
			int posend = this->ContentType.Find(CRLF,posstart);
			if(posend==-1)
				posend = this->ContentType.GetLength()-1;
			//WARNING: don't use this->ContentType here (boundary is case sensitive)
			Boundary = "--" + ContentType.Mid(posstart+9,posend-posstart-8); //RFC: CRLF + "--" + followed by boundary parameter
		}
		if(this->ContentType.Left(19)=="multipart/form-data")
			IsMultiPartFormData = true;

	}else{
		//assume empty content-type url encoded as well to scan exploits (RFC: empty = text/plain)
		IsUrlEncoded = (this->ContentType=="" || this->ContentType.Left(33)=="application/x-www-form-urlencoded");
		IsTextPlain = (this->ContentType=="" || this->ContentType.Left(10)=="text/plain");

		if(!IsUrlEncoded){
			IsText =	(this->ContentType.Left(5)=="text/" || 
						this->ContentType.Left(16)=="application/json" ||
						this->ContentType.Left(20)=="application/soap+xml" ||
						this->ContentType.Left(16)=="application/wrml" ||
						this->ContentType.Left(16)=="application/yaml" ||
						this->ContentType.Left(18)=="application/x-yaml"
						);

			IsBinary = !IsText;

			IsUTF8Encoded = this->ContentType.Left(30)=="application/x-www-utf8-encoded";
		}
	}
}

CString CMIME::GetHeader(CString& Entity, CString Header, LPCTSTR Default)
{
	CString value = Default;
	int length = Header.GetLength() + 3;
	int posstart = Entity.Find(CRLF + Header + ' ');
	if(posstart>-1 && posstart<Entity.GetLength()-length){
		int posend = Entity.Find(CRLF,posstart+length);
		if(posend>-1 && posend<=Entity.Find(CRLFCRLF))
			value = Entity.Mid(posstart+length,posend-posstart-length);
	}
	return value;
}
