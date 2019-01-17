/*
    AQTRONIX C++ Library
    Copyright 2002-2007 Parcifal Aertssen

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
// Logger.cpp: implementation of the CLogger class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "FileName.h"
#include "StringHelper.h"
#include "Logger.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/* CHANGELOG
 *	2012.02.23 Added HasEntry() for logging allowed request if not already flushed
 *	2011.01.07 Added syslog logging + split Buffer into Timestamp + Message
 *	2009.07.08 Added LogFileFormat variable instead of hard coded in define CLOGGER_LOG_FORMAT
 *  2007.07.17 Fixed bug when logging in local timezone, NewEntry() would log time in GMT
 *  2006.10.28 Added overloads for CStringList&
 *  2006.06.26 Added Append() overloads
 *             Changed itoa() with CStringHelper::Safe_IntToAscii()
 *  2006.01.08 Added date to TIMEFORMAT
 *  2005.11.02 Changed default constructor behaviour: Enabled(false)
 *			   added EnableLogging = true parameter to function SetLogDir()
 *	2005.06.06 Added ODBC logging
 *  2003.10.23 Removed #Version directive (confusion with W3C #Version)!
 *  2003.09.12 At run-time change of GMT <-> LocalTime logging instead of #defines
 *  2003.09.12 Print exact time in #Date directive instead of 00:00:00 
 *  2003.08.31 Fixed bug in calculation of localtime & GMT difference (wrong figure when 1st of month)
 *  2003.08.31 Fixed bug when changing timezone while running: call _tzset() before GetCurrentTime()
 *  2003.08.31 Changed SetHeader function (instead of string, it is now with directives)
 *  2003.08.08 Removed bug: there was no field separator between date and second field
 *	2003.08.08 Changed to GMT logging
 *	2003.06.08 Added NewEntryNoTimestamp() (needed this for CPacketFiltering class)
 *	2003.05.26 Removed SetRetention function in constructor (otherwise it would delete old logs)
 *	2003.05.17 Changed Retention: Retention<1 means not used instead of 1 day retention!
 *	2003.05.17 Changed DeleteOldLogs() - using CFile::Remove() instead of remove()
 *	2003.05.04 Added MaxLogItem & MaxLogLine
 *	2003.03.24 Initial version finished
 */

/* FEATURES REJECTED
 * - W3C extended logging (http://www.w3.org/TR/WD-logfile) because it is made for
 *   web server logging only (client/server, simple field separator, and exact same log
 *   format for each entry).
 */


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CLogger::CLogger():
	LogDir(_T("")),
	LogFileName(_T("")),
	Timestamp(0),
	Message(_T("")),
	Enabled(false),
	Retention(28), 
	DirectiveSoftware(_T("")),
	DirectiveOptional(_T("")),
	DirectiveFields(_T("")),
	UseHeader(false),
	GMTLogging(true)
#ifdef ENABLE_ODBC
,UseODBC(false)
#endif
{
	//initialize the logger
	MaxLogItem = 96000;
	MaxLogLine = 128000;
	FilenameFormat = CLOGGER_DEFAULT_LOG_FORMAT;
#ifdef ENABLE_SYSLOG
	Syslog.Enabled = false;
#endif
}

CLogger::CLogger(LPCTSTR ld,int ret):
	LogDir(_T("")),
	LogFileName(_T("")),
	Timestamp(0),
	Message(_T("")),
	Enabled(false),
	Retention(ret), 
	DirectiveSoftware(_T("")),
	DirectiveOptional(_T("")),
	DirectiveFields(_T("")),
	UseHeader(false),
	GMTLogging(true)
#ifdef ENABLE_ODBC
,UseODBC(false)
#endif
{
	//initialize the logger
	MaxLogItem = 96000;
	MaxLogLine = 128000;
	FilenameFormat = CLOGGER_DEFAULT_LOG_FORMAT;
	SetLogDir(ld);
#ifdef ENABLE_SYSLOG
	Syslog.Enabled = false;
#endif
}

CLogger::~CLogger()
{
	//flush remaining buffer
	Flush();
}

void CLogger::Append(const CString& msg)
{
	if (Enabled) {
		//Append msg to buffer
		Message += CLOGGER_FIELD_SEPARATOR;
		Message += msg.Left(MaxLogItem);
	}
}

void CLogger::AppendEscape(CString& msg)
{
	msg.Replace('\r',' ');
	msg.Replace('\n',' ');
	Append(msg);
}

void CLogger::Append(const int i)
{
	Append(CStringHelper::Safe_IntToAscii(i));
}

void CLogger::Append(const double d)
{
	Append(CStringHelper::Safe_DoubleToAscii(d));
}

void CLogger::Append(const CStringList& List)
{
	POSITION pos;
	pos = List.GetHeadPosition();
	while(pos!=NULL){
		Append(List.GetNext(pos));
	}
}

void CLogger::SetLogDir(const CString& d, const bool EnableLogging)
{
	//You should not call this function between
	//calls to Append() function!!! Otherwise
	//your appends to the log entry will be discarded!

	//Change LogDir and update the logfile
	if(d!=LogDir){
		Enabled=EnableLogging;
		Flush();
		LogDir = d;
		if (d.Right(1) != _T("\\") && d.Right(1) != _T("/"))
			LogDir += _T("\\");
		CFileName::CreatePath(d); //create the path if it does not exist
		CurrentLog.SetFileName(LogDir + LogFileName);
	}
}

void CLogger::SetRetention(const int ret)
{
	//Change retention and delete old logfiles
	//according to the new retention period
	if(Retention != ret){
		Retention = ret;
		DeleteOldLogs();
	}
}

void CLogger::UpdateClock()
{
	//Update LogDate and associated logfile
	_tzset();
	CString fn;
	if(GMTLogging){
		fn = CTime::GetCurrentTime().FormatGmt(FilenameFormat);
	}else{
		fn = CTime::GetCurrentTime().Format(FilenameFormat);
	}
	if (fn != LogFileName){
		LogFileName = fn;
		CurrentLog.SetFileName(LogDir + LogFileName);
		if(UseHeader)
			CurrentLog.WriteLine(GetHeader());
		DeleteOldLogs();
	}
}

void CLogger::DeleteOldLogs()
{
	if (Enabled) {
		//Delete old logfiles (see retention)
		//in the LogDir folder
		try{
			if(Retention>0){
				CTime old = CTime::GetCurrentTime();
				old -= CTimeSpan((Retention) * SECS_IN_DAY);
				CString fn;
				for(int i=0;i<100;i++){
					if(GMTLogging){
						fn = LogDir + old.FormatGmt(FilenameFormat);
					}else{
						fn = LogDir + old.Format(FilenameFormat);
					}
					try{
						CSandboxFile::Remove(LPCTSTR(fn));
					}catch(CFileException* e){
						e->Delete(); //do nothing
					}
					old -= CTimeSpan(SECS_IN_DAY);
				}
			}
		}catch(...){
			//do nothing with error
		}
	}
}

void CLogger::Flush()
{
	//You should call this function at the end of your logging entry
	//Write the (not empty) buffer to the logfile
	if (Message.GetLength()>0) {

		CString LogMsg(_T(""));
		CString date(_T(""));
		CString time(_T(""));

		//timestamp
		if(Timestamp!=0){
			if(GMTLogging){
				date = Timestamp.FormatGmt(CLOGGER_DATEFORMAT);
				time = Timestamp.FormatGmt(CLOGGER_TIMEFORMAT);
			}else{
				date = Timestamp.Format(CLOGGER_DATEFORMAT);
				time = Timestamp.Format(CLOGGER_TIMEFORMAT);
			}
			LogMsg = date + CLOGGER_FIELD_SEPARATOR + time + CLOGGER_FIELD_SEPARATOR;
		}

		//message
		LogMsg += Message.Left(MaxLogLine);
		
		//log file
		CurrentLog.WriteLine(LogMsg);

		//ODBC
#ifdef ENABLE_ODBC
		if(UseODBC){
			LogODBC(Timestamp,Message);
		}
#endif

		//syslog
#ifdef ENABLE_SYSLOG
		if(Syslog.Enabled){
			Syslog.Send(Timestamp,Message);
		}
#endif

		Message = _T("");
		Timestamp = 0;
	}
}

void CLogger::NewEntry(const CString& msg)
{
	//if logging is enabled
	if (Enabled) {
		Flush();//flush buffer
		UpdateClock();//Update LogDate and possibly the logfile to the new date
		Timestamp = CTime::GetCurrentTime();
		Message = msg.Left(MaxLogItem);//add possibly a msg to the buffer (can be empty)
	}
}

void CLogger::NewEntry(const CStringList& List)
{
	//if logging is enabled
	if (Enabled) {
		POSITION pos;
		pos = List.GetHeadPosition();
		CString msg = _T("");
		if(pos!=NULL){
			msg = List.GetNext(pos);
		}
		NewEntry(msg);	//even if empty, start a new entry
		while(pos!=NULL){
			Append(List.GetNext(pos));
		}
	}
}

void CLogger::NewEntryFlush(const CString& msg)
{
	if(Enabled){
		NewEntry(msg.Left(MaxLogItem));	//make new log entry
		Flush();		//and flush it immediately to the logfile
	}
}

void CLogger::NewEntryFlush(const CStringList& List)
{
	if(Enabled){
		NewEntry(List);	//make new log entry
		Flush();		//and flush it immediately to the logfile
	}
}

bool CLogger::HasEntry()
{
	return Message.GetLength()>0;
}

void CLogger::Cancel()
{
	//clear buffer
	Message = _T("");
}

void CLogger::SetMaxLogItem(int size)
{
	if(size>0)
		MaxLogItem = size;
}

void CLogger::SetMaxLogLine(int size)
{
	if(size>0)
		MaxLogLine = size;
}

void CLogger::NewEntryNoTimestamp(const CString &msg)
{
	//if logging is enabled
	if (Enabled) {
		Flush();//flush buffer
		UpdateClock();//Update LogDate and possibly the logfile to the new date
		Timestamp = 0;
		Message = msg.Left(MaxLogItem);//add possibly a msg to the buffer (can be empty)
	}
}

void CLogger::NewEntryFlushNoTimestamp(const CString &msg)
{
	if(Enabled){
		NewEntryNoTimestamp(msg.Left(MaxLogItem));	//make new log entry
		Flush();		//and flush it immediately to the logfile
	}
}

void CLogger::SetHeader(LPCTSTR pSoftware, LPCTSTR pOptional)
{
	UseHeader = true;

	//#Software
	if(pSoftware!=NULL)
		DirectiveSoftware = pSoftware;

	//#Optional
	if(pOptional!=NULL)
		DirectiveOptional = pOptional;
}

void CLogger::SetHeaderFields(CStringList &FieldList)
{
	UseHeader = true;

	//#Fields
	POSITION pos;
	pos = FieldList.GetHeadPosition();
	if(pos!=NULL){
		DirectiveFields = _T("");
		while(pos!=NULL){
			DirectiveFields += FieldList.GetNext(pos);
			if(pos!=NULL)
				DirectiveFields += CLOGGER_FIELD_SEPARATOR;
		}	
	}
}

CString CLogger::GetHeader()
{
	CString str(_T(""));
	_tzset();

	//#Software
	if(DirectiveSoftware.GetLength()>0){
		str += _T("#Software: ");
		str += DirectiveSoftware;
		str += _T("\r\n");
	}

	//#Optional
	if(DirectiveOptional.GetLength()>0){
		str += DirectiveOptional;
		str += _T("\r\n");
	}

	//#Date
	str += _T("#Date: ");
	if(GMTLogging){
		str += CTime::GetCurrentTime().FormatGmt(_T("%Y-%m-%d %H:%M:%S"));
	}else{
		str += CTime::GetCurrentTime().Format(_T("%Y-%m-%d %H:%M:%S"));
	}
	str += _T("\r\n");

	//#LogTime
	str += _T("#LogTime: ");
	if(GMTLogging){
		str += _T("GMT (Local");
		str += GetGMTDifference();
		str += _T(")\r\n");
	}else{
		str += _T("LocalTime (GMT");
		str += GetLocalDifference();
		str += _T(")\r\n");
	}
		
	//#Fields
	if(DirectiveFields.GetLength()>0){
		str += _T("#Fields: ");
		str += DirectiveFields;
		str += _T("\r\n");
	}

	if(str.Right(2)==_T("\r\n"))
		str = str.Left(str.GetLength()-2);

	return str;
}

 CString CLogger::GetGMTDifference()
{
	// Compute difference between GMT and local time
	CString gmtstr;
	_tzset();
	
	CTime time = CTime::GetCurrentTime();
	//VC 6.0
	//tm tgmt = *(time.GetGmtTm(NULL));
	//tm tloc = *(time.GetLocalTm(NULL));
	//VC.NET
	struct tm tloc;	tloc = *(time.GetLocalTm(&tloc));
	struct tm tgmt;	tgmt = *(time.GetGmtTm(&tgmt));
	return ToTimeDifferenceString(tgmt,tloc);
}

CString CLogger::GetLocalDifference()
{
	// Compute difference between local time and GMT
	_tzset();

	CTime time = CTime::GetCurrentTime();
	//VC 6.0
	//tm tloc = *(time.GetLocalTm(NULL));
	//tm tgmt = *(time.GetGmtTm(NULL));
	//VC.NET
	struct tm tloc;	tloc = *(time.GetLocalTm(&tloc));
	struct tm tgmt;	tgmt = *(time.GetGmtTm(&tgmt));
	return ToTimeDifferenceString(tloc,tgmt);
}

CString CLogger::ToTimeDifferenceString(struct tm t1, struct tm t2)
{
	CString gmtstr;
	int dif(0);
	int daydif = (t1.tm_yday) - (t2.tm_yday);
	if (daydif>1){
		daydif = -1;
	}else{
		if(daydif<-1)
			daydif = 1;
	}
	dif += daydif*24;
	dif += (t1.tm_hour) - (t2.tm_hour);
	if(dif>0){
		gmtstr = _T("+");
	}else if(dif<0){
		gmtstr = _T("-");
	}else{
		gmtstr = _T(" ");
	}
	dif = abs(dif);
	if (dif<10) gmtstr += _T("0");
	gmtstr += CStringHelper::Safe_IntToAscii(dif);
	gmtstr += _T(":");
	dif = (t1.tm_min) - (t2.tm_min);
	dif = abs(dif);
	if (dif<10) gmtstr += _T("0");
	gmtstr += CStringHelper::Safe_IntToAscii(dif);
	
	return gmtstr;
}


#ifdef ENABLE_ODBC

bool CLogger::LogODBC(CTime& Timestamp, CString Msg)
{
	try{
		if(AfxGetInstanceHandle()!=NULL){ //after DllMain call (otherwise IIS crashes)
			CString date;
			if(GMTLogging){
				date = Timestamp.FormatGmt(CLOGGER_ODBCFORMAT);
			}else{
				date = Timestamp.Format(CLOGGER_ODBCFORMAT);
			}
			//TODO: ODBC - use bindparameters
			Msg.Replace(_T("'"),_T("''"));
			return ODBC.Execute("INSERT INTO [" + LogTable + "] VALUES('" + date + "','" + Msg + "')");
		}
		return false;
	}catch(...){
		UseODBC = false;
		return false;
	}
}

bool CLogger::SetODBC(CString ConnectionString, CString Table)
{
	if(ConnectionString.GetLength()>0 && Table.GetLength()>0){
		UseODBC = true;
		LogTable = Table;
		LogTable.Replace('[',' ');
		LogTable.Replace(']',' ');
		ODBC.SetDSN(ConnectionString);
		/*
		 * Your application may fail with an "Access Violation" error message
		 * when you use ODBC or DAO in the InitInstance or DLLMain functions of a DLL
		 * http://kbalertz.com/Feedback.aspx?kbNumber=147629
		 */
		//return ODBC.Open(ConnectionString); //do this later (crashes IIS)
		return true;
	}else{
		UseODBC = false;
		ODBC.Close();
		return false;
	}
}
#endif
