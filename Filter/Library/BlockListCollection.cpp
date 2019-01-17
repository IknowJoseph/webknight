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

#include "BlockListCollection.h"

CBlockListCollection::CBlockListCollection()
{

}

CBlockListCollection::~CBlockListCollection()
{
	RemoveAll();
}

void CBlockListCollection::Load(CString path, LPCTSTR filter)
{
	CFileFind finder;
	BOOL ok = finder.FindFile(path + filter);
	while(ok){
		ok = finder.FindNextFile();
		if(!finder.IsDots() && !finder.IsDirectory()){
			LoadList(finder.GetFilePath());
		}
	}
	finder.Close();
}

void CBlockListCollection::LoadList(CString filename)
{
	CBlockList* b = new CBlockList();
	if(b->Load(filename))
		AddTail(b);
	else
		delete b;
}

void CBlockListCollection::RemoveAll()
{
	POSITION pos = GetHeadPosition();
	while(pos!=NULL){
		delete GetNext(pos);
	}
	CObList::RemoveAll();
}

bool CBlockListCollection::UpdateAll()
{
	POSITION pos = GetHeadPosition();
	CBlockList* b;
	bool ret = false;
	while(pos!=NULL){
		b = (CBlockList*) GetNext(pos);
		if(b->Update())
			ret = true;
	}
	return ret;
}