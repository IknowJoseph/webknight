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
// ODBCConnection.cpp: implementation of the CODBCConnection class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
//#define _WIN32_WINNT 0x501//CoInitializeEx()
//#include "objbase.h"	//CoInitializeEx()
#include "ODBCConnection.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


/* CHANGELOG
 *  2013.05.24 Switched from ADO to MFC database connection for IIS issue
 *  2005.07.06 Class created
 */

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CODBCConnection::CODBCConnection(LPCTSTR DSN)
{
	SetDSN(DSN);
	//Open(); //don't do this now: use lazy initialization...
}

CODBCConnection::~CODBCConnection()
{
	Close();
}

bool CODBCConnection::Open(LPCTSTR DSN)
{
	//close existing connection
	Close();

	//set new DSN
	SetDSN(DSN);

	//open connection
	return Open();
}

bool CODBCConnection::Open()
{
	if(Connection.IsOpen()){
		//already open
		SetError(_T("Already open"));
		return false;
	}else{
		//only open if DSN is known
		if(DSN==_T("")){
			SetError(_T("Invalid DSN"));
			return false;
		}else{
			return OpenConnection();
		}
	}
}

bool CODBCConnection::OpenConnection()
{
	try{

		//TODO: ODBC - time-outs
		Connection.SetLoginTimeout(2); //default is 15

		//if(Connection.Open(NULL,FALSE,FALSE,"ODBC;" + DSN,FALSE)){
		if(Connection.OpenEx(DSN, CDatabase::noOdbcDialog)){
			//open successful
			Connection.SetQueryTimeout(1); //default is 15
			return true;
		}else{
			//open failed
			SetError(_T("Could not open connection"));
			return false;
		}

	}catch(CDBException* e){
		//DB error
		SetError(e);
		e->Delete();
		return false;
	}catch(...){
		//fatal error
		SetError(_T("OpenConnection() fatal error"));
		return false;
	}
}

void CODBCConnection::Close()
{
	try{

		//close if open
		if(Connection.IsOpen()){
			Connection.Close();
		}

	}catch(CDBException* e){
		//DB error
		SetError(e);
		e->Delete();
	}catch(...){
		//fatal error
		SetError(_T("Close() fatal error"));
	}
}

void CODBCConnection::SetDSN(LPCTSTR DSN)
{
	//set new DSN string
 	CODBCConnection::DSN = DSN;
}

bool CODBCConnection::Execute(LPCTSTR SQL, HSTMT hstmt)
{
	try{

		if(!Connection.IsOpen()){
			OpenConnection();
		}
		if(Connection.IsOpen()){
			if(hstmt)
				Connection.BindParameters(hstmt);

			Connection.ExecuteSQL(SQL);
			//execute successful
			return true;
		}else{
			//connection not open
			SetError(_T("Could not execute: connection closed"));
			return false;
		}

	}catch(CDBException* e){
		//DB error
		SetError(e);
		e->Delete();
	}catch(...){
		//fatal error
		SetError(_T("Execute() fatal error"));
	}
	return false;
}

CString CODBCConnection::GetError()
{
	//return error messages
	return Error;
}

void CODBCConnection::SetError(LPCTSTR ErrMsg)
{
	//set error message
	Error = ErrMsg;
#ifdef _DEBUG
	AfxMessageBox(ErrMsg);
#endif
}

void CODBCConnection::SetError(CDBException* e)
{
	UINT nMaxError = 1024;
	TCHAR Msg[1024] = _T("");
	if(e->GetErrorMessage(Msg,nMaxError))
		SetError(Msg);
	else
		SetError(_T("CDBException"));
}

