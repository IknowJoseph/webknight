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
// IPRangeList.cpp: implementation of the CIPRangeList class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "IPRangeList.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/* Changelog
 * 2016.03.06 Tabulator character also seen as start of comments
 * 2013.04.17 IPv6 Ready (using IIPRange and IIPAddress...)
 * 2013.04.10 Cleanup IsInList(LPCTSTR IP) now first converts IP to CIPAddress
 * 2012.02.03 Added Count()
 * 2006.07.30 Added Enumerate(CStringArray&) and ToString()
 * 2005.10.02 Added AddIPRange(CIPRange&)
 *            Changed parameters CString to LPCTSTR
 * 2004.01.16 First version of class finished
 * 2003.10.15 Created class for MailKnight
 */

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CIPRangeList::CIPRangeList()
{

}

CIPRangeList::~CIPRangeList()
{
	RemoveAll();
}

bool CIPRangeList::AddIPRange(IIPRange& Range)
{
	RangeList.AddTail(&Range);
	return true;
}

bool CIPRangeList::AddIPRange(CString Range)
{
	IIPRange* p = NULL;
	int pos = Range.Find(':');
	int posc = Range.FindOneOf(_T(" \t"));
	if(pos>-1 && (posc==-1 || pos<posc)){
		p = new CIP6Range();
	}else{
		p = new CIP4Range();
	}
	if(p != NULL && p->SetIPRange(Range)){
		RangeList.AddTail(p);
		return true;
	}else{
		delete p;
		return false;
	}
}

bool CIPRangeList::Enumerate(CStringList &List)
{
	RemoveAll();
	POSITION pos = List.GetHeadPosition();
	while(pos!=NULL){
		AddIPRange(List.GetNext(pos));
	}
	return true;
}

bool CIPRangeList::Enumerate(CStringArray &List)
{
	RemoveAll();
	INT_PTR size = List.GetSize();
	for(INT_PTR i=0; i<size; i++){
		AddIPRange(List[i]);
	}
	return true;
}

bool CIPRangeList::IsInList(CString IP)
{
	/*
	 * return true if IP is in the list
	 */
	unsigned char version = 0;
	int pos = IP.Find(':');
	int posc = IP.FindOneOf(_T(" \t"));
	if(pos>-1 && (posc==-1 || pos<posc)){
		version = IPV6_SIZE;
	}else{
		version = IPV4_SIZE;
	}
	switch(version){
		case IPV4_SIZE:
			{
				CIP4Address IPv4;
				if(IPv4.SetIP(IP)){
					return IsInList(IPv4);
				}else{
					return false;
				}
			}
			break;
		case IPV6_SIZE:
			{
				CIP6Address IPv6;
				if(IPv6.SetIP(IP)){
					return IsInList(IPv6);
				}else{
					return false;
				}
			}
			break;
	}
	return false;
}

bool CIPRangeList::IsInList(IIPAddress& IP)
{
	/*
	 * return true if IP is in the list
	 */
	POSITION pos;
	IIPRange* ipr = NULL;
	pos = RangeList.GetHeadPosition();
	switch(IP.GetSize()){
		case IPV4_SIZE:
			while (pos != NULL){
				ipr = (IIPRange*)RangeList.GetNext(pos);
				if(IPV4_SIZE == ipr->GetSize()){ //only if same IP version
					if( ((CIP4Range*)ipr)->IsInRange((CIP4Address&)IP) ){
						return true;
					}
				}
			}
			return false;
		case IPV6_SIZE:
			while (pos != NULL){
				ipr = (IIPRange*)RangeList.GetNext(pos);
				if(IPV6_SIZE == ipr->GetSize()){ //only if same IP version
					if( ((CIP6Range*)ipr)->IsInRange((CIP6Address&)IP) ){
						return true;
					}
				}
			}
			return false;
	}
	return false;
}

bool CIPRangeList::IsEmpty()
{
	return (RangeList.GetHeadPosition()==NULL);
}

void CIPRangeList::RemoveAll()
{
	POSITION pos = RangeList.GetHeadPosition();
	while(pos!=NULL){
		delete RangeList.GetNext(pos);
	}
	RangeList.RemoveAll();
}

CString CIPRangeList::ToString(LPCTSTR Separator)
{
	CString ret("");
	POSITION pos = RangeList.GetHeadPosition();
	while(pos!=NULL){
		IIPRange* p = (IIPRange*) RangeList.GetNext(pos);
		ret += p->ToString();
		if(pos!=NULL){
			ret += Separator;
		}
	}
	return ret;
}

unsigned int CIPRangeList::Count()
{
	return RangeList.GetCount();
}

unsigned int CIPRangeList::GetByteCount()
{
	unsigned int total = 0;
	POSITION pos = RangeList.GetHeadPosition();
	while(pos!=NULL){
		IIPRange* p = (IIPRange*) RangeList.GetNext(pos);
		total += p->GetSize() * 4 /* not 2 */;
	}
	return total;
}

