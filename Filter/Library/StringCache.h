/*
    AQTRONIX C++ Library
    Copyright 2004-2006 Parcifal Aertssen

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
// StringCache.h: interface for the CStringCache class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_STRINGCACHE_H__8F46B9FD_CE38_499F_9CD9_212D28418834__INCLUDED_)
#define AFX_STRINGCACHE_H__8F46B9FD_CE38_499F_9CD9_212D28418834__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CStringCacheItem: public CObject{
public:
	CString str;
	CString str2;
	CTime time;
	CStringCacheItem(CString item = "",CString value = ""):str(item),str2(value),time(CTime::GetCurrentTime()){};
	CString ToString(bool ShowStr2 = true){
		return time.Format("%a %b %d %H:%M:%S") + " - " + str + " " + ((ShowStr2)?str2:"*");
	}
};


class CStringCache  
{
public:
	//mutations
	void Add(CString& item);
	void Add(CString& item, CString& value);
	void AddNotInCache(CString& Item, CString& Value);
	void AddNotInCache(CString& Item);
	void Delete(CString& Item, CString& Value);
	void Delete(CString& Item);
	void Update(CString& Item);
	void Update(CString& Item, CString& Value);

	//lookup + count
	unsigned int Count(CString& Item, CString& Value);
	unsigned int Count(CString &Item);
	unsigned int Count();
	bool Exists(CString& Item, CString& Value, CTime& StartTime);
	bool Exists(CString& Item, CString& Value);
	bool Exists(CString& Item, CTime &StartTime);
	bool Exists(CString& item);

	unsigned int GetByteCount();
	bool IsFull();
	bool LookupValue(CString &Item, CString& Value);
	CTime Lookup(CString& Item, CString& Value, CTime& StartTime);
	CTime Lookup(CString& Item, CString& Value);
	CTime Lookup(CString &Item, CTime &StartTime);
	CTime Lookup(CString& item);

	void SetMaxItems(unsigned int MaxItems);
	void SetMaxAge(CTimeSpan& MaxAge);
	void Clear();
	CString ToString(LPCTSTR Separator, bool ShowValue = true);
	void ToMap(CMapStringToString& map);

	//constructor/destructor
	CStringCache(CTimeSpan MaxAge=(1,0,0,0),unsigned int MaxItems=32000);
	virtual ~CStringCache();

protected:
	inline void DeleteMax();
	void Purge();
	CObList cache;
	CTimeSpan max_age;
	unsigned int max_items;
	unsigned int count_items;
};

#endif // !defined(AFX_STRINGCACHE_H__8F46B9FD_CE38_499F_9CD9_212D28418834__INCLUDED_)
