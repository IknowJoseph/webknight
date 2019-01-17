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
#include "StdAfx.h"
#include "RegexCache.h"

CRegexCache::CRegexCache(void)
{
}

CRegexCache::~CRegexCache(void)
{
	RemoveAll();
}

CAtlRegExp<>* CRegexCache::Lookup(const CString& pattern)
{
	CAtlRegExp<>* regex = NULL;
	//use regex cache
	if(!CMapStringToPtr::Lookup(pattern,(void*&)regex)){
		regex = new CAtlRegExp<>();
		REParseError status = regex->Parse(pattern);
		if(status == REPARSE_ERROR_OK){
			SetAt(pattern,(void*&)regex);
		}else{
			SetAt(pattern,NULL);
			delete regex;
			regex = NULL;
		}
	}
	return regex;
}

bool CRegexCache::Match(const CString &Data, const CString &Pattern)
{
	CAtlRegExp<>* regex = Lookup(Pattern);
	if(regex!=NULL){ //NULL = regex syntax error
		CAtlREMatchContext<> mc;
		return regex->Match(Data,&mc) == TRUE;
	}
	return false;
}

void CRegexCache::RemoveAll()
{
	//cleanup regex cache
	CString k;
	CAtlRegExp<>* regex;
	POSITION pos = GetStartPosition();
	while(pos!=NULL){
		GetNextAssoc(pos,k,(void*&)regex);
		delete regex;
	}
	CMapStringToPtr::RemoveAll();
}
