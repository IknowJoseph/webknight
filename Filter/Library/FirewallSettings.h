/*
    AQTRONIX C++ Library
    Copyright 2005-2014 Parcifal Aertssen

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
// FirewallSettings.h: interface for the CFirewallSettings class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_FIREWALLSETTINGS_H__77074A5D_1BB1_4646_9C96_C6A36C438951__INCLUDED_)
#define AFX_FIREWALLSETTINGS_H__77074A5D_1BB1_4646_9C96_C6A36C438951__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

//#define ENABLE_ODBC
#define ENABLE_SYSLOG

#include "Settings.h"
#include "IPRangeList.h"
#include "StringCache.h"
#include "RegexCache.h"
#include "Action.h"

class CFirewallSettings : public CSettings  
{
protected:
	virtual bool ReadFromFileINI(LPCTSTR fn);
	virtual bool WriteToFileINI(LPCTSTR fn);
	virtual CString GetXMLLogging(CFirewallSettings& d);
	virtual CString GetXMLResponseHandling(CFirewallSettings& d);
	virtual bool ParseXML(CString& key, CString& val);

public:
	class _Statistics{
	public:
		CStringCache Alerts;
		CStringCache Messages;
	} Statistics;

	CRegexCache regex_cache;

	class _IPRanges{
	public:
		//don't forget to add them in the webadmin
		CIPRangeList Monitor;
		CIPRangeList Deny;
		CIPRangeList Exclude;
		CIPRangeList Admin;
		CIPRangeList AllowDeniedHosts;
	} IPRanges;

	bool WriteToFileXML(LPCTSTR fn);
	void LoadDefaults();
	CString ToXML();

	CFirewallSettings();
	virtual ~CFirewallSettings();

	//RESPONSE HANDLING
	class _Response{
	public:
		bool LogOnly;
	}Response;
	
	//LOGGING
	class _Logging{
	public:
		CString LogDirectory;
		bool Enabled;
		bool PerWebsite;
		bool PerProcessOwner;
		bool PerProcess;
		int Retention;
		CString FilenameFormat;
		bool LogClientIP;
		bool LogUserName;
		bool UseGMT;
		bool LogAllowed;
#ifdef ENABLE_ODBC
		bool ODBCEnabled;
		CString ODBCDSN;
		CString ODBCTable;
#endif
#ifdef ENABLE_SYSLOG
		bool SyslogEnabled;
		CString SyslogServer;
		int SyslogPort;
		int SyslogPriority;
#endif
	}Logging;

protected:
	CString LogDirDefault;

};

#endif // !defined(AFX_FIREWALLSETTINGS_H__77074A5D_1BB1_4646_9C96_C6A36C438951__INCLUDED_)
