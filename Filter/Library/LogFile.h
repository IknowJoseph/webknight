/*
    AQTRONIX C++ Library
    Copyright 2002-2006 Parcifal Aertssen

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
// LogFile.h: interface for the CLogFile class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_LOGFILE_H__7FEFF5F8_9957_40C5_92CE_A1DEE3B38AE0__INCLUDED_)
#define AFX_LOGFILE_H__7FEFF5F8_9957_40C5_92CE_A1DEE3B38AE0__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "SandboxFile.h"

class CLogFile : private CSandboxFile  
{
public:
	bool WriteLine(CString Msg);
	bool NewLine();
	CString GetLastError() const;
	void SetLastError(LPCTSTR ErrMsg);
	void SetLastError(CFileException* ex);
	void SetFileName(CString&);
	CString GetFileName();
	bool Write(CString);
	void Close();
	bool Open();
	CLogFile(CString f = _T(""));
	virtual ~CLogFile();

protected:
	CString Error;
	CString FileName;
	bool IsOpen;
};

#endif // !defined(AFX_LOGFILE_H__7FEFF5F8_9957_40C5_92CE_A1DEE3B38AE0__INCLUDED_)
