/*
    AQTRONIX C++ Library
    Copyright 2012-2013 Parcifal Aertssen

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
// CSyslogSocket.h: interface for the CSyslogSocket class.
//
//////////////////////////////////////////////////////////////////////
#pragma once

// CSyslogSocket command target

//for Windows 2000
//http://support.microsoft.com/kb/955045
#include <ws2tcpip.h>
//If you get an error on this line below, make sure you have the Platform SDK installed
#include <wspiapi.h>

#define SYSLOG_MFC

#ifdef SYSLOG_MFC
#include <afxsock.h>
#endif

class CSyslogSocket
#ifdef SYSLOG_MFC
	: public CAsyncSocket
#endif
{
protected:
	virtual CString DetectHostname();

	void ReportError(UINT uErr);
	void ReportError();

#ifndef SYSLOG_MFC
	//direct API
	WSADATA wsaData;
    SOCKET syslogSocket;
	//CSocketWnd socketWnd;
#endif
	sockaddr_in toAddress;
	
public:
	bool m_IsReady;
	CString LastError;
	CString SourceHostname;
	void ReportError(LPCTSTR Message);

	virtual void Initialize(CString& DestinationHost, UINT DestinationPort);
	virtual bool SendNotice(const char* lpBuf, int nBufLen); 
	virtual void Destroy();

	CSyslogSocket();
	virtual ~CSyslogSocket();
};


