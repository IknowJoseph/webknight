/*
    AQTRONIX C++ Library
    Copyright 2011-2013 Parcifal Aertssen

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
// SyslogDevice.h: interface for the CSyslogDevice class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "SyslogDevice.h"

//2011.01.07 class created
//2012.02.21 created SyslogSocket class for testing W2K compatibility (CAsyncSocket constructor calls GetAddrInfo)
//now the constructor is only called if syslog is enabled
//W2K error message: 'getaddrinfo' could not be located in the dynamic link library WS2_32.
//http://support.microsoft.com/kb/955045
//2012.04.27 BUGFIX: syslog works under W2K, fixed: 2 additional headers are now included (see SyslogSocket.h)
//2013.10.28 IPv6 ready

/*
 * SYSLOG RFC 3164
 * http://tools.ietf.org/html/rfc3164
 *
 * SYSLOG = <PRI> TIMESTAMP HOSTNAME MSG
 * PRI = number
 * TIMESTAMP = "Mmm dd hh:mm:ss" (without quotes)
 * HOSTNAME = string without domain or IPv4 or IPv6
 * MSG = string or TAG + CONTENT
 * TAG = application name: or application name[pid]:
 * CONTENT = string
 */

#define CSYSLOGDEVICE_TIMESTAMP _T("%b %d %H:%M:%S")

CSyslogDevice::CSyslogDevice():DestinationPort(514),DestinationHost(_T("localhost")),Enabled(false),ApplicationName(_T(""))
{
	socket = NULL;
}

CSyslogDevice::~CSyslogDevice()
{
	if(socket!=NULL){
		socket->Destroy();
		delete socket;
		socket = NULL;
	}
}

CString CSyslogDevice::Initialize()
{
	socket = new CSyslogSocket();
	socket->Initialize(DestinationHost,DestinationPort);
	return socket->LastError;
}

bool CSyslogDevice::Send(CTime& Timestamp, CString& Msg)
{
	if(socket==NULL || !socket->m_IsReady)
		return false;

	try{
		//pri + timestamp
		CString LogMsg = _T("<");
		LogMsg += Priority;
		LogMsg += _T(">") + Timestamp.Format(CSYSLOGDEVICE_TIMESTAMP) + _T(" ");
		//source hostname
		if(socket->SourceHostname!=_T("")){
			LogMsg += socket->SourceHostname + _T(" ");
		}
		//application name
		if(ApplicationName!=_T("")){
			LogMsg += ApplicationName + _T(": ");
		}
		//message
		LogMsg += Msg;
		//send
		return socket->SendNotice(LogMsg.GetBuffer(0),LogMsg.GetLength());
	}catch(...){
		socket->ReportError(_T("Fatal error sending syslog message"));
		return false;
	}
}