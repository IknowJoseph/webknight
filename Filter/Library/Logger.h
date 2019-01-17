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
// Logger.h: interface for the CLogger class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_LOGGER_H__081BF6DC_4410_406A_A3A5_4F61505BBD9F__INCLUDED_)
#define AFX_LOGGER_H__081BF6DC_4410_406A_A3A5_4F61505BBD9F__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "LogFile.h"

#define ENABLE_SYSLOG
#ifdef ENABLE_SYSLOG
#include "SyslogDevice.h"
#endif

//TODO: ODBC - in settings + table schema on website (2 columns: Timestamp, Text)
//#define ENABLE_ODBC
#ifdef ENABLE_ODBC
#include "ODBCConnection.h"
#endif

#define SECS_IN_DAY 86400					//number of seconds in a day
#define CLOGGER_DEFAULT_LOG_FORMAT "%y.%m.%d.log"	//format of the filename
#define CLOGGER_FIELD_SEPARATOR " ; "

#define CLOGGER_DATEFORMAT "%Y-%m-%d"
#define CLOGGER_TIMEFORMAT "%H:%M:%S"
#define CLOGGER_ODBCFORMAT "%Y-%m-%d %H:%M:%S"

class CLogger : private CObject  
{
public:
	//syslog
#ifdef ENABLE_SYSLOG
	CSyslogDevice Syslog;
#endif
#ifdef ENABLE_ODBC
	bool UseODBC;
	CString LogTable;
	CODBCConnection ODBC;
	bool SetODBC(CString ConnectionString, CString Table);
	bool LogODBC(CTime& Timestamp, CString Msg);
#endif
	CLogFile CurrentLog;	//the logfile itself
	bool GMTLogging;
	CString FilenameFormat; //filename format of log file

	void SetHeaderFields(CStringList& FieldList);
	void NewEntryFlushNoTimestamp(const CString& msg="");
	void NewEntryNoTimestamp(const CString& msg="");
	void SetMaxLogLine(int size);
	void SetMaxLogItem(int size);
	void SetHeader(LPCTSTR pSoftware = NULL, LPCTSTR pOptional = NULL);
	void Cancel();
	bool Enabled;
	void NewEntryFlush(const CString& msg="");
	void NewEntryFlush(const CStringList& List);
	void NewEntry(const CString& msg="");
	void NewEntry(const CStringList& List);
	bool HasEntry();
	void Flush();
	void SetRetention(const int ret);
	void SetLogDir(const CString& d, const bool EnableLogging = true);
	void AppendEscape(CString&);
	void Append(const CString&);
	void Append(const int i);
	void Append(const double d);
	void Append(const CStringList& List);

	CLogger();
	CLogger(LPCTSTR ld,int ret=28);
	virtual ~CLogger();

protected:
	CString GetHeader();

	//header
	bool UseHeader;
	CString DirectiveSoftware;
	CString DirectiveOptional;
	CString DirectiveFields;

	int MaxLogLine;
	int MaxLogItem;
	void DeleteOldLogs();
	void UpdateClock();
	CString LogFileName;	//the date in filename format for the logfile
	CString LogDir;			//the folder to put the log files
	int Retention;			//period to keep old log files (in days)

	CTime Timestamp;		//log entry timestamp
	CString Message;		//log entry message

	CString GetLocalDifference();
	CString GetGMTDifference();
	CString ToTimeDifferenceString(struct tm t1, struct tm t2);

};

#endif // !defined(AFX_LOGGER_H__081BF6DC_4410_406A_A3A5_4F61505BBD9F__INCLUDED_)
