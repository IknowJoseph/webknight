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
// StringCache.cpp: implementation of the CStringCache class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "StringCache.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/* CHANGELOG
 *
 *	2017.11.24	Added IsFull()
 *  2016.10.18  Added LookupValue()
 *  2015.12.01  Added Update() for Session hijacking monitoring
 *  2013.10.23	Added DeleteMax()
 *	2012.12.14  Added ToString() for WebKnight statistics page
 *	2005.09.01	Added functions AddItemNotInCache()
 *	2004.??.??	Initial version finished
 *
 */

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CStringCache::CStringCache(CTimeSpan MaxAge,unsigned int MaxItems):max_age(MaxAge),max_items(MaxItems),count_items(0)
{
	if(max_age<0){
		max_age=0;
	}
}

CStringCache::~CStringCache()
{
	Clear();
}

void CStringCache::Add(CString &item)
{
	//Purge Cache
	Purge();
	
	//check for max items
	DeleteMax();

	//add new item
	CStringCacheItem* citem = new CStringCacheItem(item);
	if(citem!=NULL){
		cache.AddTail(citem);
		count_items++;
	}
}

void CStringCache::Add(CString &item, CString &value)
{
	//Purge Cache
	Purge();
	
	//check for max items
	DeleteMax();

	//add new item
	CStringCacheItem* citem = new CStringCacheItem(item,value);
	if(citem!=NULL){
		cache.AddTail(citem);
		count_items++;
	}
}

void CStringCache::Clear()
{
	POSITION pos;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		delete cache.GetNext(pos);
	}
	cache.RemoveAll();
	count_items=0;
}

void CStringCache::Purge()
{
	if(max_age>0){
		POSITION pos; POSITION oldpos;
		CStringCacheItem* pitem = NULL;
		CTime boundary = CTime::GetCurrentTime() - max_age;
		pos = cache.GetHeadPosition();
		while(pos!=NULL){
			oldpos = pos;
			pitem = (CStringCacheItem*)cache.GetNext(pos);
			if(pitem->time<boundary){
				delete pitem;
				cache.RemoveAt(oldpos);
				count_items--;
			}else{
				return;
			}
		}
	}
}

bool CStringCache::Exists(CString &Item)
{
	//Purge Cache
	Purge();
	//Lookup item
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->str==Item){
			return true;
		}
	}
	return false;
}

bool CStringCache::Exists(CString &Item, CTime &StartTime)
{
	//Purge Cache
	Purge();
	//Lookup item
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->time>StartTime && pitem->str==Item){
			return true;
		}
	}
	return false;
}

bool CStringCache::Exists(CString &Item, CString &Value)
{
	//Purge Cache
	Purge();
	//Lookup item
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->str==Item && pitem->str2==Value){
			return true;
		}
	}
	return false;
}

bool CStringCache::Exists(CString &Item, CString &Value, CTime &StartTime)
{
	//Purge Cache
	Purge();
	//Lookup item
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->time>StartTime && pitem->str==Item && pitem->str2==Value){
			return true;
		}
	}
	return false;
}

bool CStringCache::IsFull()
{
	return Count()==this->max_items && max_items>0;
}

CTime CStringCache::Lookup(CString &Item)
{
	//Purge Cache
	Purge();
	//Lookup item
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->str==Item){
			return pitem->time;
		}
	}
	return CTime(0);
}

CTime CStringCache::Lookup(CString &Item, CTime &StartTime)
{
	//Purge Cache
	Purge();
	//Lookup item
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->time>StartTime && pitem->str==Item){
			return pitem->time;
		}
	}
	return StartTime;
}

CTime CStringCache::Lookup(CString &Item, CString &Value)
{
	//Purge Cache
	Purge();
	//Lookup item
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->str==Item && pitem->str2==Value){
			return pitem->time;
		}
	}
	return CTime(0);
}

CTime CStringCache::Lookup(CString &Item, CString &Value, CTime &StartTime)
{
	//Purge Cache
	Purge();
	//Lookup item
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->time>StartTime && pitem->str==Item && pitem->str2==Value){
			return pitem->time;
		}
	}
	return StartTime;
}

bool CStringCache::LookupValue(CString &Item, CString& Value)
{
	//Purge Cache
	Purge();
	//Lookup item
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->str==Item){
			Value = pitem->str2;
			return true;
		}
	}
	return false;
}

void CStringCache::SetMaxAge(CTimeSpan &MaxAge)
{
	if(MaxAge>=0){
		max_age = MaxAge;
		//Purge Cache
		Purge();
	}
}

void CStringCache::SetMaxItems(unsigned int MaxItems)
{
	max_items = MaxItems;
	//check for max items
	if(max_items>0){
		POSITION pos; POSITION posold;
		while(count_items>max_items){
			pos = cache.GetHeadPosition();
			posold = pos;
			delete cache.GetNext(pos);
			cache.RemoveAt(posold);
			count_items--;
		}
	}
}

unsigned int CStringCache::Count(CString &Item)
{
	//Purge Cache
	Purge();

	//Count number of references
	POSITION pos;
	CStringCacheItem* pitem;
	unsigned int count(0);
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*)cache.GetNext(pos);
		if(pitem->str==Item)
			count++;
	}
	return count;
}

unsigned int CStringCache::Count(CString &Item, CString &Value)
{
	//Purge Cache
	Purge();

	//Count number of references
	POSITION pos;
	CStringCacheItem* pitem;
	unsigned int count(0);
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*)cache.GetNext(pos);
		if(pitem->str==Item && pitem->str2==Value)
			count++;
	}
	return count;
}

unsigned int CStringCache::Count()
{
	//Purge Cache
	Purge();

	//Count number of references
	return count_items;
}

void CStringCache::Delete(CString &Item)
{
	//delete item
	POSITION pos; POSITION oldpos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		oldpos = pos;
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->str==Item){
			delete pitem;
			cache.RemoveAt(oldpos);
			count_items--;
		}
	}
}

void CStringCache::Delete(CString &Item, CString &Value)
{
	//delete item
	POSITION pos; POSITION oldpos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		oldpos = pos;
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->str==Item && pitem->str2==Value){
			delete pitem;
			cache.RemoveAt(oldpos);
			count_items--;
		}
	}
}

void CStringCache::Update(CString &Item)
{
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->str==Item){
			pitem->time = CTime::GetCurrentTime();
			return;
		}
	}
}

void CStringCache::Update(CString &Item, CString &Value)
{
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*) cache.GetNext(pos);
		if(pitem->str==Item && pitem->str2==Value){
			pitem->time = CTime::GetCurrentTime();
			return;
		}
	}
}

void CStringCache::DeleteMax()
{
	if(max_items>0){
		if(count_items>max_items-1){
			POSITION pos; POSITION posold;
			pos = cache.GetHeadPosition();
			posold = pos;
			if(pos!=NULL){
				delete cache.GetNext(pos);
				cache.RemoveAt(posold);
				count_items--;
			}
		}
	}
}

void CStringCache::AddNotInCache(CString &Item)
{
	if(!Exists(Item)){
		Add(Item);
	}
}

void CStringCache::AddNotInCache(CString &Item, CString &Value)
{
	if(!Exists(Item, Value)){
		Add(Item, Value);
	}
}

CString CStringCache::ToString(LPCTSTR Separator, bool ShowValue)
{
	CString ret("");
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*)cache.GetNext(pos);
		ret += pitem->ToString(ShowValue);
		if(pos!=NULL){
			ret += Separator;
		}
	}
	return ret;
}

void CStringCache::ToMap(CMapStringToString& map)
{
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*)cache.GetNext(pos);
		map.SetAt(pitem->str,pitem->str2);
	}
}

unsigned int CStringCache::GetByteCount()
{
	unsigned int total = 0;
	POSITION pos;
	CStringCacheItem* pitem;
	pos = cache.GetHeadPosition();
	while(pos!=NULL){
		pitem = (CStringCacheItem*)cache.GetNext(pos);
		total += (pitem->str.GetLength() + pitem->str2.GetLength() + 2) * sizeof(TCHAR) + sizeof(CTime);
	}
	return total;
}

