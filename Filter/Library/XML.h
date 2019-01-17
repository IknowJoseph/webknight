/*
    AQTRONIX C++ Library
    Copyright 2005-2015 Parcifal Aertssen

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
// XML.h: interface for the CXML class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_XML_H__26C9DD0B_EEFF_49B3_BB1C_5407C9A9990C__INCLUDED_)
#define AFX_XML_H__26C9DD0B_EEFF_49B3_BB1C_5407C9A9990C__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CXML  
{
public:
	static CString Decode(LPCTSTR str);
	static CString Encode(LPCTSTR str);
	static CString AttributeValue(CString tag, CString par);
	static CString TagName(CString tag);
	static CString Declaration();

	CXML();
	virtual ~CXML();

};

#endif // !defined(AFX_XML_H__26C9DD0B_EEFF_49B3_BB1C_5407C9A9990C__INCLUDED_)
