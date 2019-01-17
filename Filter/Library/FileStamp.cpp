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
#include "FileStamp.h"

CFileStamp::CFileStamp(void)
{
}

CFileStamp::~CFileStamp(void)
{
}

void CFileStamp::Set(LPCTSTR /* don't use CString for CFileException badPath exception */ filename, CSandboxFile& file)
{
	FileName = filename;
	CFileStatus fs;
	if(file.GetStatus(fs))
		Time = fs.m_mtime;
}

void CFileStamp::Set(CString filename)
{
	FileName = filename;
	CFileStatus fs;
	if(CSandboxFile::GetStatus(filename,fs))
		Time = fs.m_mtime;
}

bool CFileStamp::HasChanged()
{
	CFileStatus fs;
	if(CSandboxFile::GetStatus(FileName,fs))			//if fileinformation could be retrieved
		return Time != fs.m_mtime;		//if timestamp is different

	return false;
}

