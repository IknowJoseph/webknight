/*
    AQTRONIX C++ Library
    Copyright 2003-2013 Parcifal Aertssen

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
// IPRangeList.h: interface for the CIPRangeList class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_IPRANGELIST_H__3CE39C6A_82B2_48C8_882D_08A71C37AEC1__INCLUDED_)
#define AFX_IPRANGELIST_H__3CE39C6A_82B2_48C8_882D_08A71C37AEC1__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "IPRange.h"

class CIPRangeList  
{
public:
	bool AddIPRange(IIPRange& Range);
	bool AddIPRange(CString Range);
	
	bool Enumerate(CStringList& list);
	bool Enumerate(CStringArray& list);
	
	unsigned int GetByteCount();
	bool IsEmpty();
	bool IsInList(IIPAddress& IP);
	bool IsInList(CString IP);

	void RemoveAll();
	CString ToString(LPCTSTR Separator);
	unsigned int Count();

	CIPRangeList();
	virtual ~CIPRangeList();

protected:
	CObList RangeList;
};

#endif // !defined(AFX_IPRANGELIST_H__3CE39C6A_82B2_48C8_882D_08A71C37AEC1__INCLUDED_)
