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
#pragma once

class CMIME
{
public:
	CString ContentType;
	CString Boundary;

	bool IsMultiPart;
	bool IsMultiPartFormData;
	bool IsUrlEncoded;
	bool IsUTF8Encoded;
	bool IsTextPlain;
	bool IsText;
	bool IsBinary;

	static CString GetHeader(CString& Entity, CString Header, LPCTSTR Default);
	void Parse(CString ContentType);
	CMIME(CString ContentType);
	CMIME(void);
	~CMIME(void);
};
