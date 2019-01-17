/*
    AQTRONIX C++ Library
    Copyright 2005-2013 Parcifal Aertssen

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
// ODBCConnection.h: interface for the CODBCConnection class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_ODBCCONNECTION_H__933CE776_E9F9_499C_841F_1A00E13D078F__INCLUDED_)
#define AFX_ODBCCONNECTION_H__933CE776_E9F9_499C_841F_1A00E13D078F__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <afxdb.h> //CDatabase

#include "ProcessHelper.h"

class CODBCConnection

{
public:

	bool Open(LPCTSTR DSN);
	bool Open();
	void Close();
	bool Execute(LPCTSTR SQL, HSTMT hstmt = NULL);
	CString GetError();
	void SetDSN(LPCTSTR DSN);

	CODBCConnection(LPCTSTR DSN = _T(""));
	virtual ~CODBCConnection();

protected:
	bool OpenConnection();
	bool CloseConnection();
	void SetError(LPCTSTR ErrMsg);
	void SetError(CDBException* e);

	CString Error;
	CString DSN;
	CDatabase Connection;
};

#endif // !defined(AFX_ODBCCONNECTION_H__933CE776_E9F9_499C_841F_1A00E13D078F__INCLUDED_)
