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
#include "BlockList.h"
#include "FileName.h"
#include "StringHelper.h"

CBlockList::CBlockList(void)
{
}

CBlockList::~CBlockList(void)
{
}

bool CBlockList::Load(CString filename)
{
	CString contents;
	if(CFileName::ReadFileToString(filename,contents,INT_MAX)){
		Stamp.Set(filename);
		CFileName fn(filename);
		Name = fn.FileName;
		CString eol = CStringHelper::DetectEOL(contents);
		CStringList iplist;
		CStringHelper::Split(iplist,contents,eol);
		return ip.Enumerate(iplist);
	}
	return false;
}

bool CBlockList::Update()
{
	if(Stamp.HasChanged())
		return Load(Stamp.FileName);

	return false;
}
