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
// HTML.h: interface for the CHTML class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_HTML_H__E6F6FC0C_E5CC_4185_8862_7C869D71AB96__INCLUDED_)
#define AFX_HTML_H__E6F6FC0C_E5CC_4185_8862_7C869D71AB96__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "URL.h"

class CHTML  
{
public:
	static CString ExtractAllTags(CString& HTML, CString TagName);
	static CString ExtractTag(CString& HTML, CString TagName, int Start=0);
	static CString FilterTag(CString& HTML, CString TagName);
	static CString Decode(LPCTSTR html);
	static CString& Decode(CString& html);
	static CString& Encode(CString& text);
	static CString HTMLToTags(CString& html);
	static CString HTMLToText(CString& html);
	CHTML();
	virtual ~CHTML();
};

#endif // !defined(AFX_HTML_H__E6F6FC0C_E5CC_4185_8862_7C869D71AB96__INCLUDED_)
