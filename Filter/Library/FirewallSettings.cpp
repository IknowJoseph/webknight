/*
    AQTRONIX C++ Library
    Copyright 2005-2006 Parcifal Aertssen

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
// FirewallSettings.cpp: implementation of the CFirewallSettings class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "FirewallSettings.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CFirewallSettings::CFirewallSettings()
{
	LoadDefaults(); //always load defaults (failover redundancy)
}

CFirewallSettings::~CFirewallSettings()
{

}

CString CFirewallSettings::GetXMLLogging(CFirewallSettings& d)
{
	CString xml("");
	//Logging
	WRITE_XML_BOOL(Logging,Enabled,"Enabled","Enable or disable logging.\r\nRequires restart of firewall!")
	xml += XML.ToXML("Log_Directory","Text",Logging.LogDirectory,LogDirDefault,"The directory where the log files will be placed.\r\nRequires restart of firewall!");
	WRITE_XML_STRING(Logging,FilenameFormat,"Log_Filename_Format","The format of the generated log file names. Syntax is C++ 'strftime': A=weekday, B=month name, d=day of month, j=day of year, m=month, U=week of year, y=year(99), Y=year(9999). Requires restart!")
	WRITE_XML_BOOL(Logging,UseGMT,"Use_GMT","Log dates and times in GMT/UTC.\r\nRequires restart of firewall!")
	WRITE_XML_BOOL(Logging,PerProcess,"Per_Process_Logging","Make a unique log file per web server process. This is for web servers that can host the filter in more than 1 process concurrently.\r\nRequires restart of firewall!")
	WRITE_XML_BOOL(Logging,PerProcessOwner,"Per_Process_Owner_Logging","Make a unique log file per web server process owner. The application pool identity will be part of the log file name (recommended for IIS 7.0 SP2 and higher).\r\nRequires restart of firewall!")
	WRITE_XML_INT(Logging,Retention,"Log_Retention","The rotation period (in days) to keep the log files.\r\nRequires restart of firewall!")
#ifdef ENABLE_ODBC
	WRITE_XML_BOOL(Logging,ODBCEnabled,"ODBC_Enabled","Log to ODBC database.\r\nRequires restart of firewall!")
	WRITE_XML_STRING(Logging,ODBCDSN,"Log_ODBC_DSN","ODBC connection string like: 'DSN=mydsn;DATABASE=mydatabase;UID=myuser;PWD=mypass;'.\r\nRequires restart of firewall!")
	WRITE_XML_STRING(Logging,ODBCTable,"Log_ODBC_Table","Database table to log to. This table needs three columns in this order: date,time,message.\r\nRequires restart of firewall!")
#endif
#ifdef ENABLE_SYSLOG
	//syslog
	WRITE_XML_BOOL(Logging,SyslogEnabled,"Syslog_Enabled","Enable forwarding log entries to syslog server.\r\nRequires restart of firewall!");
	WRITE_XML_STRING(Logging,SyslogServer,"Syslog_Server","The syslog server to forward the messages to.\r\nRequires restart of firewall!");
	WRITE_XML_INT(Logging,SyslogPort,"Syslog_Port","The UDP port number of the syslog server.\r\nRequires restart of firewall!");
	WRITE_XML_INT(Logging,SyslogPriority,"Syslog_Priority","The syslog priority of the messages.\r\nRequires restart of firewall!");
#endif

	WRITE_XML_BOOL(Logging,LogAllowed,"Log_Allowed","In addition to logging blocked requests you can log allowed requests as well. This has high performance impact on heavy loaded systems and is not recommended!")
	WRITE_XML_BOOL(Logging,LogClientIP,"Log_Client_IP","Log the client IP address.")
	WRITE_XML_BOOL(Logging,LogUserName,"Log_User_Name","Log the username the client is logged on with.")

	return xml;
}

CString CFirewallSettings::GetXMLResponseHandling(CFirewallSettings& d)
{
	CString xml("");
	//Response Handling
	WRITE_XML_BOOL(Response,LogOnly,"Response_Log_Only","If an attack is detected, only log and do not block it. If you want the firewall to go completely stealth, also disable the 'Response Headers' in 'Response Monitor'.")
	return xml;
}

bool CFirewallSettings::WriteToFileINI(LPCTSTR fn)
{
	//Response handling
	WRITE_INI_BOOL(Response,LogOnly)

	//Logging
	WRITE_INI_BOOL(Logging,Enabled)
	WRITE_INI_STRING(Logging,LogDirectory)
	WRITE_INI_STRING(Logging,FilenameFormat)
	WRITE_INI_BOOL(Logging,UseGMT)
	WRITE_INI_BOOL(Logging,PerProcess)
	WRITE_INI_BOOL(Logging,PerProcessOwner)
	WRITE_INI_INT(Logging,Retention)

#ifdef ENABLE_ODBC
	WRITE_INI_BOOL(Logging,ODBCEnabled)
	WRITE_INI_STRING(Logging,ODBCDSN)
	WRITE_INI_STRING(Logging,ODBCTable)
#endif
#ifdef ENABLE_SYSLOG
	//syslog
	WRITE_INI_BOOL(Logging,SyslogEnabled)
	WRITE_INI_STRING(Logging,SyslogServer)
	WRITE_INI_INT(Logging,SyslogPort)
	WRITE_INI_INT(Logging,SyslogPriority)
#endif

	WRITE_INI_BOOL(Logging,LogClientIP)
	WRITE_INI_BOOL(Logging,LogUserName)
	WRITE_INI_BOOL(Logging,LogAllowed)


	return true;
}

bool CFirewallSettings::ReadFromFileINI(LPCTSTR fn)
{
	const int sz = SETTINGS_MAX_INI_BUF_SIZE;
	char buf[sz];

	//Response
	READ_INI_BOOL(Response,LogOnly)

	//Logging
	READ_INI_BOOL(Logging,Enabled)
	READ_INI_STRING(Logging,LogDirectory)
	READ_INI_STRING(Logging,FilenameFormat)
	READ_INI_BOOL(Logging,UseGMT)
	READ_INI_BOOL(Logging,PerProcess)
	READ_INI_BOOL(Logging,PerProcessOwner)
	READ_INI_INT(Logging,Retention)

#ifdef ENABLE_ODBC
	READ_INI_BOOL(Logging,ODBCEnabled)
	READ_INI_STRING(Logging,ODBCDSN)
	READ_INI_STRING(Logging,ODBCTable)
#endif
#ifdef ENABLE_SYSLOG
	//syslog
	READ_INI_BOOL(Logging,SyslogEnabled)
	READ_INI_STRING(Logging,SyslogServer)
	READ_INI_INT(Logging,SyslogPort)
	READ_INI_INT(Logging,SyslogPriority)
#endif

	READ_INI_BOOL(Logging,LogClientIP)
	READ_INI_BOOL(Logging,LogUserName)
	READ_INI_BOOL(Logging,LogAllowed)

	return true;
}

bool CFirewallSettings::ParseXML(CString &key, CString &val)
{
	//if not a valid key
	if (key=="")
		return false;

	CString name = CXML::Decode(CXML::TagName(key));
	
	//Response Handling
	PARSE_XML_BOOL(Response,LogOnly,"Response_Log_Only")

	//Logging
	else PARSE_XML_BOOL(Logging,Enabled,"Enabled")
	else PARSE_XML_STRING(Logging,LogDirectory,"Log_Directory")
	else PARSE_XML_STRING(Logging,FilenameFormat,"Log_Filename_Format")
	else PARSE_XML_BOOL(Logging,UseGMT,"Use_GMT")
	else PARSE_XML_BOOL(Logging,PerProcess,"Per_Process_Logging")
	else PARSE_XML_BOOL(Logging,PerProcessOwner,"Per_Process_Owner_Logging")
	else PARSE_XML_INT(Logging,Retention,"Log_Retention",(int))
	else PARSE_XML_BOOL(Logging,LogAllowed,"Log_Allowed_Requests")
	else PARSE_XML_BOOL(Logging,LogAllowed,"Log_Allowed")
	else PARSE_XML_BOOL(Logging,LogClientIP,"Log_Client_IP")
	else PARSE_XML_BOOL(Logging,LogUserName,"Log_User_Name")
#ifdef ENABLE_ODBC
	else PARSE_XML_BOOL(Logging,ODBCEnabled,"ODBC_Enabled")
	else PARSE_XML_STRING(Logging,ODBCDSN,"Log_ODBC_DSN")
	else PARSE_XML_STRING(Logging,ODBCTable,"Log_ODBC_Table")
#endif
#ifdef ENABLE_SYSLOG
	else PARSE_XML_BOOL(Logging,SyslogEnabled,"Syslog_Enabled")
	else PARSE_XML_STRING(Logging,SyslogServer,"Syslog_Server")
	else PARSE_XML_INT(Logging,SyslogPort,"Syslog_Port",(int))
	else PARSE_XML_INT(Logging,SyslogPriority,"Syslog_Priority",(int))
#endif
	else{
		return false;
	}
	return true;
}

CString CFirewallSettings::ToXML()
{
	CString xml("");
	CFirewallSettings d;
	xml += GetXMLResponseHandling(d);
	xml += GetXMLLogging(d);
	return xml;
}

void CFirewallSettings::LoadDefaults()
{
	Response.LogOnly = false;			//if true, log only (for testing)
}

bool CFirewallSettings::WriteToFileXML(LPCTSTR fn)
{
	return XML.WriteEntityToFile(fn,"CFirewallSettings",ToXML());
}
