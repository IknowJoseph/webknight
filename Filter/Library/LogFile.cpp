/*
    AQTRONIX C++ Library
    Copyright 2002-2012 Parcifal Aertssen

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
// LogFile.cpp: implementation of the CLogFile class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "LogFile.h"
#include "FileName.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/* CHANGELOG
 *
 *	2017.07.13 Clear Error when changing filename
 *  2015.12.22 Switched to CSandboxFile instead of CFile
 *  2014.12.31 Fixed empty error message when CFile.Open failed (needs call to AfxSetResourceHandle(CProcessHelper::GetCurrentModule());
 *  2012.12.16 Added GetFileName()
 *	2003.05.26 Removed bug in errorhandling: added e->Delete();
 *	2003.03.24 Initial version finished
 */

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CLogFile::CLogFile(CString f):IsOpen(false),FileName(_T(""))
{
	SetFileName(f);
}

CLogFile::~CLogFile()
{
	Close();
}

bool CLogFile::Open()
{
	if (FileName == _T("")) {
		SetLastError(_T("No filename specified!"));
		return false;
	}

	if (!IsOpen) {
		//open it
		int openret;
		CFileException fe;
		openret = CSandboxFile::Open(CFileName::GetDrivePrefix() + FileName,CFile::modeCreate|CFile::modeNoTruncate|CFile::modeWrite|CFile::shareDenyWrite, &fe);
		if (openret > 0) {
			IsOpen = true;
			try{
				CSandboxFile::SeekToEnd();
				return true;
			}catch(CFileException* e){
				SetLastError(e);
				e->Delete();
				return false;
			}
		}else{
			//Error = "Could not open log file: " + FileName;
			//DWORD errcode = ::GetLastError();
			//if(errcode != ERROR_SUCCESS){
			//	Error += " (Error code " + CStringHelper::Safe_DWORDToAscii(errcode) + ": " + CProcessHelper::GetErrorDescription(errcode) + ")";
			//}
			SetLastError(&fe);
			//fe.Delete(); //don't delete this instance!
			return false;
		}
	}else{
		SetLastError(_T("Logfile is already open: ") + FileName);
		return false;
	}
}

void CLogFile::Close()
{
	//if file is open, close it and set IsOpen to false
	if(IsOpen){
		try{
			CSandboxFile::Close();
			IsOpen = false;
		}catch(CFileException* e){
			SetLastError(e);
			e->Delete();
		}
	}
}

bool CLogFile::Write(CString Msg)
{
	//if file is not open, then open it
	if (!IsOpen){
		Open();
	}
	//if it is open, then write to it
	if (IsOpen){
		try {
			CSandboxFile::Write(Msg,_tcslen(Msg));
			return true;
		}catch(CFileException* e){
			SetLastError(e);
			e->Delete();
			return false;
		}
	} else{
		return false;
	}
}

void CLogFile::SetFileName(CString& pf)
{
	//if filename is not the same
	if (pf != FileName) {
		FileName = pf;	//change filename
		Error = "";		//clear previous error
		if (IsOpen) {	//reopen if logfile is open
			Close();
			Open();
		}
	}
}

CString CLogFile::GetFileName()
{
	return FileName;
}

CString CLogFile::GetLastError() const
{
	return Error;
}

void CLogFile::SetLastError(LPCTSTR ErrMsg)
{
	Error = ErrMsg;
#ifdef _DEBUG
	AfxMessageBox(ErrMsg);
#endif
}

void CLogFile::SetLastError(CFileException* ex)
{
	TCHAR errmsg[1024];
	if(ex->GetErrorMessage(errmsg,1024))
		SetLastError((CString)errmsg); //needs cast to CString for CFile::Open &fe
	else
		SetLastError(_T("CFileException"));
}

bool CLogFile::NewLine()
{
	return Write(_T("\r\n"));
}

bool CLogFile::WriteLine(CString msg)
{
	msg += _T("\r\n");
	return Write(msg);
}