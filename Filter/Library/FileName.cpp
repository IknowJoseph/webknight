/*
    AQTRONIX C++ Library
    Copyright 2002-2013 Parcifal Aertssen

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
// FileName.cpp: implementation of the CFileName class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "FileName.h"
#include "StringHelper.h"
#include  <io.h>
#include "SandboxFile.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/* CHANGELOG
 *
 *  2015.12.22 Switched to CSandboxFile instead of CFile
 *  2013.10.12 Fixed SetFileName Path="" instead of Path=fn when no path present
 *  2013.04.16 Added FileExists (from CSettings class)
 *  2012.12.27 Added copy constructor
 *  2007.07.18 Added errorhandling in SetFileName() for WebKnight bug
 *	2005.09.08 Added ReadFileToString() and WriteStringToFile()
 *	2005.07.05 Added lpSecurityAttributes to CreatePath() and removed
 *             redundant code (SetFileName & operator =)
 *	2003.10.16 Added SetFileName() and Exists functions
 *	2003.05.18 Added overloaded functions DeleteFile(fn) and CreatePath()
 *	2003.05.04 Added DeleteFile()
 *	2003.03.24 Initial version finished
 */

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CFileName::CFileName(CString fn)
{
	SetFileName(fn);
}

CFileName::~CFileName()
{

}

//copy constructor
CFileName::CFileName(const CFileName& fn)
{
	this->FullPath = fn.FullPath;
	this->FullPathLCase = fn.FullPathLCase;
	this->Path = fn.Path;
	this->PathLCase = fn.PathLCase;
	this->FileName = fn.Extension;
	this->FileNameLCase = fn.FileNameLCase;
	this->Extension = fn.Extension;
	this->ExtensionLCase = fn.ExtensionLCase;
}

CFileName& CFileName::operator =(const CString& fn)
{
	SetFileName(fn);
	return *this;
}

void CFileName::CreatePath(CString wsPath,LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
	DWORD attr; 
	int pos;
	
	//Check for trailing slash
	if (wsPath.Right(1)=='\\')
		wsPath = wsPath.Left(wsPath.GetLength()-1); //remove trailing '\'
		
	//Look for existing object
	attr = GetFileAttributes(LPCTSTR(wsPath));
	if (0xFFFFFFFF /* INVALID_FILE_ATTRIBUTES (undefined in VS6) */ == attr){ //doesn't exist yet 
		pos = wsPath.ReverseFind('\\');
		if (pos!=-1) {
			//Create parent dirs
			CreatePath(wsPath.Left(pos));
		} 
		//Create node
		CreateDirectory(LPCTSTR(wsPath), lpSecurityAttributes);
	}
}

bool CFileName::DeleteFile()
{
	return DeleteFile(FullPath);
}

void CFileName::CreatePath()
{
	CreatePath(Path);
}

bool CFileName::DeleteFile(const CString &fn)
{
	try{
		CSandboxFile::Remove(fn);
		return true;
	}catch(CFileException* e){
		e->Delete();
		return false;
	}
}

bool CFileName::Exists(const CString &fn)
{
	try{
		return (_taccess(fn,0)!=-1);
	}catch(...){
		return false;
	}
}

bool CFileName::Exists()
{
	return Exists(FullPath);
}

bool CFileName::FileExists(LPCTSTR fn)
{
	DWORD attr = GetFileAttributes(fn);
	return (attr != 0xFFFFFFFF /* INVALID_FILE_ATTRIBUTES (undefined in VS6) */ && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

void CFileName::SetFileName(CString fn)
{
	//set full path
	FullPath = fn;

	//split filename from full name (from full path)
	int i; int j; int p;
	i = fn.ReverseFind('/');
	j = fn.ReverseFind('\\');
	i>j?p=i:p=j;
	if(p!=-1){
		Path = fn.Left(p+1);
		FileName = fn.Right(fn.GetLength()-p-1);
	}else{
		Path = _T("");
		FileName = fn;
	}
	
	//split extension from filename
	p = FileName.ReverseFind('.');
	if (p!=-1)
		Extension = FileName.Right(FileName.GetLength()-p);

	//set lowercase equivalents
	FullPathLCase = FullPath;
	PathLCase = Path;
	FileNameLCase = FileName;
	ExtensionLCase = Extension;

	//MakeLower can fail if Locale is set to Korean
	CStringHelper::Safe_MakeLower(ExtensionLCase);
	CStringHelper::Safe_MakeLower(FileNameLCase);
	CStringHelper::Safe_MakeLower(PathLCase);
	CStringHelper::Safe_MakeLower(FullPathLCase);
}

CString CFileName::GetDrivePrefix()
{
	//When no access to root of drive (for query volume information) -> access denied (even with access to folder)
	//https://connect.microsoft.com/VisualStudio/feedback/details/800932/cfile-mfc-does-not-work-with-internet-explorer-enhanced-protected-mode-cfile-open-fails
	//-> solution prepend \\?\ http://forums.codeguru.com/showthread.php?453021-CFile-Open-function-fails

	//return _T("\\\\?\\"); //Fix for CFile::Open bug when no access to volume root (works on XP/W2003, not on Windows 7/8)
	return _T("");
}

bool CFileName::ReadFileToString(LPCTSTR Path, CString &Contents, ULONGLONG MaxSize)
{
	CSandboxFile rf;
	bool ret(false);
	if(rf.Open(GetDrivePrefix() + Path,CFile::modeRead|CFile::shareDenyNone)){
		char* buf = NULL;
		try{
			const ULONGLONG rfsz = rf.GetLength();
			if(rfsz>0 && rfsz<MaxSize){
				buf = new char[rfsz+1];
				if(buf!=NULL){
					try{
						rf.Read(buf,rfsz);
						ret = true;
					}catch(CFileException* fe){
						fe->Delete();
					}
					buf[rfsz]='\0';
					if(ret)
						Contents = buf;
					delete[] buf;
				}
			}
		}catch(...){
			ret = false;
			if(buf)
				delete[] buf;
		}
		rf.Close();
	}
	return ret;
}

bool CFileName::ReadFileToString(CString &Contents,ULONGLONG MaxSize)
{
	return ReadFileToString(FullPath,Contents,MaxSize);
}

bool CFileName::WriteStringToFile(CString &Contents, LPCTSTR fn)
{
	CSandboxFile f;
	UINT Length = Contents.GetLength();
	if (f.Open(GetDrivePrefix() + fn,CFile::modeCreate|CFile::modeWrite|CFile::shareDenyWrite)>0){
		f.Write(Contents.GetBuffer(0),Length);
		f.Close();
		return true;
	}else{
		return false;
	}
}

bool CFileName::WriteStringToFile(CString &Contents)
{
	return WriteStringToFile(Contents,FullPath);	
}

