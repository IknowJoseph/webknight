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

#include "HTML.h"
#include "URL.h"
#include "StringCache.h"
#include "IPRangeList.h"

class CWebAdmin
{
public:
	static CString InstallFile(CString fn, CString src_path, CString dest_path);

	static CString BuildMenu(CString HTMLMessage);
	static CString BuildPage(CString title, CString& body);
	static CString BuildForm(CString Name, CString URL, CMapStringToString& map);
	static CString BuildParameterForm(CString Dashboard, CString Section, CMapStringToString& map, CString URL);

	static CString WarnNoScript();
	static CString AddJS();
	static CString AddTitle(CString htmltitle);
	static CString AddParagraph(CString htmltext);
	static CString AddPreformatted(CString htmltext);

	static CString ToTable(LPCTSTR Title, CStringCache& cache, bool ShowValue = true);
	static CString ToTable(LPCTSTR Title, CIPRangeList& list);
	static CString ToTable(LPCTSTR Title, CMapStringToPtr& map, LPCTSTR Column1, LPCTSTR Column2);
	static CString CollapsibleTable(LPCTSTR Title, CString& Text, unsigned int count, unsigned int size);
	static CString AddRow(CString Key, CString Value);
	static CString AddRow(CString Column1, CString Column2, CString Column3);
	static CString AddRow(CString Column1, CString Column2, CString Column3, CString Column4);
	static CString GetQueryStringValue(CString& QueryString, CString Key);

	CWebAdmin(void);
	virtual ~CWebAdmin(void);
};
