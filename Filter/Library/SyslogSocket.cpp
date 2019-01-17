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
// SyslogSocket.h: interface for the SyslogSocket class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "SyslogSocket.h"

// CSyslogSocket
CSyslogSocket::CSyslogSocket():m_IsReady(false),LastError(_T("")),SourceHostname(_T(""))
{
}

CSyslogSocket::~CSyslogSocket()
{
#ifdef SYSLOG_MFC
#else
	//direct API
	// Close our socket entirely
    closesocket(syslogSocket);
    // Cleanup Winsock
    WSACleanup();
#endif
}

void CSyslogSocket::Initialize(CString& DestinationHost, UINT DestinationPort)
{
	try{

		m_IsReady = false;
#ifdef SYSLOG_MFC
		//CAsyncSocket
		if(AfxSocketInit()==TRUE){
			SourceHostname = DetectHostname();
			if(Create(0,SOCK_DGRAM,FD_WRITE)!=TRUE){
				ReportError();
			}else{
				//IPv6
				toAddress.sin_family = AF_INET;
				toAddress.sin_port = htons(DestinationPort);
				struct addrinfo hints, *res;
				memset(&hints, 0, sizeof(hints));
				hints.ai_socktype = SOCK_DGRAM;
				hints.ai_family = NULL; //AF_INET = IPv4, AF_INET6 = IPv6
				//lookup hostname
				if(getaddrinfo(DestinationHost,NULL,&hints,&res)==0){
					toAddress.sin_addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
					freeaddrinfo(res);
				}else{
					//fallback to IPv4 lookup
					//toAddress.sin_addr.s_addr = inet_addr(DestinationHost); //IPv4 lookup
					ReportError(GetLastError());
					return;
				}
				//if(Connect(DestinationHost,DestinationPort)==TRUE) //IPv4
				if(Connect((SOCKADDR*) &toAddress, sizeof(toAddress))==TRUE)
					m_IsReady = true;
			}
		}else{
			ReportError();
		}
#else
		//direct API

		//create socket
		if( WSAStartup( MAKEWORD(2, 2), &wsaData ) != NO_ERROR )
		{
			ReportError(_T("Socket Initialization: Error with WSAStartup"));
			WSACleanup();
			return;
		}

		SourceHostname = DetectHostname();

		syslogSocket = socket(AF_INET, SOCK_DGRAM, 0);
		if (syslogSocket == INVALID_SOCKET)
		{
			ReportError(_T("Socket Initialization: Error creating socket"));
			WSACleanup();
			return;
		}

	    //bind
		toAddress.sin_family = AF_INET;
		toAddress.sin_port = htons(DestinationPort);
		struct addrinfo hints, *res;
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_family = AF_INET;
		//lookup hostname
		if(getaddrinfo(DestinationHost,NULL,&hints,&res)==0){
			toAddress.sin_addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
			freeaddrinfo(res);
		}else{
			//is already IP address
			toAddress.sin_addr.s_addr = inet_addr(DestinationHost);
		}

		if(connect(syslogSocket, (SOCKADDR*) &toAddress, sizeof(toAddress)) == SOCKET_ERROR)
		{
			ReportError();
			WSACleanup();
			return;
		}

#pragma message("***** SYSLOG is not async, define SYSLOG_MFC for asynchronous syslog *****")

		//SYSLOG - ASYNC
		//if(WSAAsyncSelect(syslogSocket,socketWnd.m_hWnd,299,FD_WRITE|FD_CLOSE)==SOCKET_ERROR){
		//	ReportError();
		//}
		//HANDLE sockEv=CreateEvent(NULL,TRUE,FALSE,NULL);
		//if(WSAEventSelect(syslogSocket,sockEv,FD_WRITE)==SOCKET_ERROR){
		//	ReportError();
		//}
		m_IsReady = true;
#endif

	}catch(...){
		ReportError();
	}
}

CString CSyslogSocket::DetectHostname()
{
	try{
		TCHAR chrComputerName[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD dwBufferSize = MAX_COMPUTERNAME_LENGTH + 1; 
		if(GetComputerName(chrComputerName,&dwBufferSize)) {
			return chrComputerName;
		} else {
			return _T("");
		} 
	}catch(...){
		return _T("");
	}
}

bool CSyslogSocket::SendNotice(const char* pBuf, int nBufLen)
{
	if(!m_IsReady)
		return false;

	try{
#ifdef SYSLOG_MFC
		//CAsyncSocket
		if(CAsyncSocket::Send(pBuf,nBufLen)==SOCKET_ERROR){
			UINT uErr = GetLastError();
			if(uErr==WSAEWOULDBLOCK){
				m_IsReady = false;
			}else{
				ReportError(uErr);
			}
			return false;
		}
#else
		//direct API
		int to_length = sizeof(sockaddr_in);
		if(sendto(syslogSocket, pBuf , nBufLen, 0, (SOCKADDR*) &toAddress, to_length)==SOCKET_ERROR){
			ReportError();
			return false;
		}
#endif
		return true;
	}catch(...){
		ReportError(_T("Fatal error sending syslog message"));
		return false;
	}
}

void CSyslogSocket::Destroy()
{
#ifdef SYSLOG_MFC
	//CAsyncSocket
	ShutDown(CAsyncSocket::both); //ignore further messages
#else
	//direct API
	shutdown(syslogSocket, SD_BOTH);
#endif
}

void CSyslogSocket::ReportError()
{
	try{
#ifdef SYSLOG_MFC
		//CAsyncSocket
		ReportError(GetLastError());
#else
		//direct API
		ReportError(WSAGetLastError());
#endif
	}catch(...){
		ReportError(_T("Fatal error in call to ReportError()"));
	}
}

void CSyslogSocket::ReportError(UINT uErr)
{
	TCHAR szError[256];
	wsprintf(szError, _T("Socket Error: %d"), uErr);
	ReportError(szError);
}

void CSyslogSocket::ReportError(LPCTSTR Message)
{
	LastError = Message;
#ifdef _DEBUG
	AfxMessageBox(Message);
#endif
}