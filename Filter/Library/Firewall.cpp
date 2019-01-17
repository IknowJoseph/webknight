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
// Firewall.cpp: implementation of the CFirewall class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Firewall.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CFirewall::CFirewall(CFirewallSettings& _Settings, CLogger& _logger):Settings(_Settings),logger(_logger)
{
	UpdateStamp.Init();
}

CFirewall::~CFirewall()
{

}

bool CFirewall::DenyChar(const char *p, char c, const char *LogMsg, const int LogType)
{
	if(strchr(p,c)!=NULL) {
		Alert(LogMsg,LogType);
		return true;
	}else{
		return false;
	}
}

bool CFirewall::DenyChar(const char *p, char c, const char *LogMsg, CStringList& Log)
{
	if(strchr(p,c)!=NULL) {
		Log.AddTail(LogMsg);
		return true;
	}else{
		return false;
	}
}

bool CFirewall::DenySpecialWhitespace(LPCTSTR Text, CString AppendText, const int LogType)
{
	bool hack(false);
	hack |= DenyChar(Text,'\r',"carriage return character" + AppendText, LogType);	//block carriage return
	hack |= DenyChar(Text,'\n',"new line character" + AppendText, LogType);			//block newline
	hack |= DenyChar(Text,'\b',"backspace character" + AppendText, LogType);		//block backspace
	hack |= DenyChar(Text,'\t',"tabulator character" + AppendText, LogType);		//block tabulator
	hack |= DenyChar(Text,'\v',"vertical tab character" + AppendText, LogType);		//block tabulator
	hack |= DenyChar(Text,'\f',"form feed character" + AppendText, LogType);		//block form feed
	return hack;
}

bool CFirewall::DenyMultipleCharacters(CString& ScanString, char c, const char *LogMsg, const int LogType)
{
	int pos = ScanString.Find(c);
	if(pos > -1 && pos != ScanString.ReverseFind(c)){
		Alert(LogMsg,LogType);
		return true;
	}else{
		return false;
	}
}

bool CFirewall::DenyString(const char *p, const char *pStr, const char *LogMsg, const int LogType)
{
	if(strstr(p,pStr)!=NULL) {
		Alert(LogMsg,LogType);
		return true;
	}else{
		return false;
	}
}

bool CFirewall::DenyString(const char *p, const char *pStr, const char *LogMsg, CStringList& Log)
{
	if(strstr(p,pStr)!=NULL) {
		Log.AddTail(LogMsg);
		return true;
	}else{
		return false;
	}
}

bool CFirewall::DenySequences(CString &ScanString, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType)
{
	CString seq;
	bool ret(false);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(ScanString.Find(seq)!=-1){
			ret = true;
			Alert(LogPre + seq + LogPost,LogType);
		}
	}
	return ret;
}

bool CFirewall::DenySequences(CString &ScanString, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log)
{
	CString seq;
	bool ret(false);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(ScanString.Find(seq)!=-1){
			ret = true;
			Log.AddTail(LogPre + seq + LogPost);
		}
	}
	return ret;
}

bool CFirewall::DenySequences(CString &ScanString1, CString& ScanString2, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType)
{
	CString seq;
	bool ret(false);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(ScanString1.Find(seq)!=-1 || ScanString2.Find(seq)!=-1){
			ret = true;
			Alert(LogPre + seq + LogPost,LogType);
		}
	}
	return ret;
}

bool CFirewall::DenySequences(CString &ScanString1, CString& ScanString2, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log)
{
	CString seq;
	bool ret(false);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(ScanString1.Find(seq)!=-1 || ScanString2.Find(seq)!=-1){
			ret = true;
			Log.AddTail(LogPre + seq + LogPost);
		}
	}
	return ret;
}

bool CFirewall::DenySequences(CStringList &ScanList1, CStringList& ScanList2, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType)
{
	CString seq;
	bool ret(false);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(IsInList(seq,ScanList1) || IsInList(seq,ScanList2)){
			ret = true;
			Alert(LogPre + seq + LogPost,LogType);
		}
	}
	return ret;
}

bool CFirewall::DenySequences(CStringList &ScanList1, CStringList& ScanList2, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log)
{
	CString seq;
	bool ret(false);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(IsInList(seq,ScanList1) || IsInList(seq,ScanList2)){
			ret = true;
			Log.AddTail(LogPre + seq + LogPost);
		}
	}
	return ret;
}

bool CFirewall::DenySequences(CStringList &ScanList, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType)
{
	if(ScanList.GetCount()<Sequences.GetCount()){
		return DenySequences(Sequences,ScanList,LogPre,LogPost,LogType);
	}else{
		CString seq;
		bool ret(false);
		POSITION pos = Sequences.GetHeadPosition();
		while(pos!=NULL){
			seq = Sequences.GetNext(pos);
			if(IsInList(seq,ScanList)){
				ret = true;
				Alert(LogPre + seq + LogPost,LogType);
			}
		}
		return ret;
	}
}

bool CFirewall::DenySequences(CStringList &ScanList, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log)
{
	if(ScanList.GetCount()<Sequences.GetCount()){
		return DenySequences(Sequences,ScanList,LogPre,LogPost,Log);
	}else{
		CString seq;
		bool ret(false);
		POSITION pos = Sequences.GetHeadPosition();
		while(pos!=NULL){
			seq = Sequences.GetNext(pos);
			if(IsInList(seq,ScanList)){
				ret = true;
				Log.AddTail(LogPre + seq + LogPost);
			}
		}
		return ret;
	}
}

int CFirewall::DenyCharactersCount(CString &ScanString, CString &Characters, CString LogPre, CString LogPost, const int LogType)
{
	int i; char c;
	int ret(0);
	for(i=0;i<Characters.GetLength();i++){
		c = Characters.GetAt(i);
		if(ScanString.Find(c)>-1){
			ret++;
			Alert(LogPre + CString(c) + LogPost,LogType);
		}
	}
	return ret;
}

int CFirewall::DenyCharactersCount(CString &ScanString, CString &Characters, CString LogPre, CString LogPost, CStringList& Log)
{
	int i; char c;
	int ret(0);
	for(i=0;i<Characters.GetLength();i++){
		c = Characters.GetAt(i);
		if(ScanString.Find(c)>-1){
			ret++;
			Log.AddTail(LogPre + CString(c) + LogPost);
		}
	}
	return ret;
}

int CFirewall::DenyCharactersCount(CString &ScanString1, CString& ScanString2, CString &Characters, CString LogPre, CString LogPost, const int LogType)
{
	int i; char c;
	int ret(0);
	for(i=0;i<Characters.GetLength();i++){
		c = Characters.GetAt(i);
		if(ScanString1.Find(c)!=-1 || ScanString2.Find(c)!=-1){
			ret++;
			Alert(LogPre + CString(c) + LogPost,LogType);
		}
	}
	return ret;
}

int CFirewall::DenyCharactersCount(CString &ScanString1, CString& ScanString2, CString &Characters, CString LogPre, CString LogPost, CStringList& Log)
{
	int i; char c;
	int ret(0);
	for(i=0;i<Characters.GetLength();i++){
		c = Characters.GetAt(i);
		if(ScanString1.Find(c)!=-1 || ScanString2.Find(c)!=-1){
			ret++;
			Log.AddTail(LogPre + CString(c) + LogPost);
		}
	}
	return ret;
}

int CFirewall::DenySequencesCount(CString &ScanString, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType)
{
	CString seq;
	int ret(0);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(ScanString.Find(seq)!=-1){
			ret++;
			Alert(LogPre + seq + LogPost,LogType);
		}
	}
	return ret;
}

int CFirewall::DenySequencesCount(CString &ScanString, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log)
{
	CString seq;
	int ret(0);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(ScanString.Find(seq)!=-1){
			ret++;
			Log.AddTail(LogPre + seq + LogPost);
		}
	}
	return ret;
}

int CFirewall::DenySequencesCount(CString &ScanString1, CString& ScanString2, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType)
{
	CString seq;
	int ret(0);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(ScanString1.Find(seq)!=-1 || ScanString2.Find(seq)!=-1){
			ret++;
			Alert(LogPre + seq + LogPost,LogType);
		}
	}
	return ret;
}

int CFirewall::DenySequencesCount(CString &ScanString1, CString& ScanString2, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log)
{
	CString seq;
	int ret(0);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(ScanString1.Find(seq)!=-1 || ScanString2.Find(seq)!=-1){
			ret++;
			Log.AddTail(LogPre + seq + LogPost);
		}
	}
	return ret;
}

int CFirewall::DenySequencesCount(CStringList &ScanList, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType)
{
	CString seq;
	int ret(0);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(IsInList(seq,ScanList)){
			ret++;
			Alert(LogPre + seq + LogPost,LogType);
		}
	}
	return ret;
}

int CFirewall::DenySequencesCount(CStringList &ScanList, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log)
{
	CString seq;
	int ret(0);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(IsInList(seq,ScanList)){
			ret++;
			Log.AddTail(LogPre + seq + LogPost);
		}
	}
	return ret;
}

int CFirewall::DenySequencesCount(CStringList &ScanList1, CStringList& ScanList2, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType)
{
	CString seq;
	int ret(0);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(IsInList(seq,ScanList1) || IsInList(seq,ScanList2)){
			ret++;
			Alert(LogPre + seq + LogPost,LogType);
		}
	}
	return ret;
}

int CFirewall::DenySequencesCount(CStringList &ScanList1, CStringList& ScanList2, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log)
{
	CString seq;
	int ret(0);
	POSITION pos = Sequences.GetHeadPosition();
	while(pos!=NULL){
		seq = Sequences.GetNext(pos);
		if(IsInList(seq,ScanList1) || IsInList(seq,ScanList2)){
			ret++;
			Log.AddTail(LogPre + seq + LogPost);
		}
	}
	return ret;
}

bool CFirewall::DenyRegex(CString& Data, CMapStringToString& Patterns,CString LogPre, CString LogPost, const int LogType)
{
	bool ret(false);
	CString k; CString v;
	POSITION pos = Patterns.GetStartPosition();
	while(pos!=NULL){
		Patterns.GetNextAssoc(pos,k,v);
		CAtlRegExp<>* regex = Settings.regex_cache.Lookup(v);
		if(regex!=NULL){ //NULL = regex syntax error
			CAtlREMatchContext<> mc;
			if(regex->Match(Data,&mc)){
				ret = true;
				Alert(LogPre + k + LogPost,LogType);
			}
		}
	}
	return ret;
}

void CFirewall::ClearCache()
{
	//cleanup regex cache
	Settings.regex_cache.RemoveAll();
}

CString CFirewall::LoadSettingFile(CString& Path, LPCTSTR SettingFile, LPCTSTR BackupFile1, LPCTSTR BackupFile2)
{
	CString strinit("INFO: Settings loaded from file: ");

	//initialize settings
	if(Settings.ReadFromFile(Path + SettingFile)){
		strinit += SettingFile;
	}else{
		if(BackupFile1!=NULL){
			if(Settings.ReadFromFile(Path + BackupFile1)){
				strinit += BackupFile1;
			}else{
				if(BackupFile2!=NULL){
					if(Settings.ReadFromFile(Path + BackupFile2)){
						strinit += BackupFile2;
					}else{
						strinit = "WARNING: Failed to load settings from " + CString(SettingFile) + ", " + BackupFile1 + " or " + BackupFile2 + " file (defaults loaded)";
					}
				}else{
					strinit = "WARNING: Failed to load settings from " + CString(SettingFile) + ", " + BackupFile1 + " file (defaults loaded)";
				}
			}
		}else{
			strinit = "WARNING: Failed to load settings from " + CString(SettingFile) + " file (defaults loaded)";
		}
	}
	return strinit;
}

CString CFirewall::SaveDefaultSettingFile(CString& Path, LPCTSTR SettingFile)
{
	//make a settings file if it doesn't exist
	if (!CFileName::FileExists(Path + SettingFile)){
		if(Settings.WriteToFile(Path + SettingFile)){
			Settings.ReadFromFile(Path + SettingFile);//for runtime update
			return "INFO: A file '" + CString(SettingFile) + "' was made with the currently loaded settings.";
		}else{
			return "WARNING: Failed to make a settings file: " + CString(SettingFile);
		}
	}
	return "";
}

CString CFirewall::InitializeLogger(LPCTSTR DefaultLogFolder, LPCTSTR SoftwareHeader, LPCTSTR Suffix)
{
	logger.SetHeader(SoftwareHeader);
	SetLoggerFields();

	CString dir = Settings.Logging.LogDirectory;
	if(dir==""){
		dir = DefaultLogFolder;
	}

	if(Settings.Logging.FilenameFormat!=""){
		logger.FilenameFormat = Settings.Logging.FilenameFormat + ".log";
	}
	//per owner logging
	if(Settings.Logging.PerProcessOwner){
		CString owner = CProcessHelper::GetCurrentUserName();
		if(owner!=""){
			//dir += owner;
			//dir += '\\';
			logger.FilenameFormat.Replace(".log","." + owner + ".log");			
		}
	}
	//per process logging
	if(Settings.Logging.PerProcess){
		DWORD id = GetCurrentProcessId();
		logger.FilenameFormat.Replace(".log","." + CStringHelper::Safe_DWORDToAscii(id) + ".log");
	}

	//suffix (for IIS Module)
	if(Suffix != NULL){
		logger.FilenameFormat.Replace(".log",CString(Suffix) + ".log");
	}

	logger.GMTLogging = Settings.Logging.UseGMT;
	logger.SetRetention(Settings.Logging.Retention);
	logger.SetLogDir(dir);
	logger.Enabled = Settings.Logging.Enabled;

	//ODBC
#ifdef ENABLE_ODBC
	if(Settings.Logging.ODBCEnabled){
		if(logger.SetODBC(Settings.Logging.ODBCDSN,Settings.Logging.ODBCTable)){
			return "INFO: ODBC logging enabled";
		}else{
			return "WARNING: ODBC logging failed at startup! Error: " + logger.ODBC.GetError();
		}
	}
#endif

	//syslog
#ifdef ENABLE_SYSLOG
	logger.Syslog.Enabled = Settings.Logging.SyslogEnabled;
	logger.Syslog.DestinationHost = Settings.Logging.SyslogServer;
	logger.Syslog.DestinationPort = Settings.Logging.SyslogPort;
	logger.Syslog.Priority = CStringHelper::Safe_IntToAscii(Settings.Logging.SyslogPriority);
	logger.Syslog.ApplicationName = SoftwareHeader;
	if(logger.Syslog.Enabled){
		CString err = logger.Syslog.Initialize();
		if(err!=""){
			return "WARNING: Syslog failed to initialize: " + err;
		}else{
			return "INFO: Syslog enabled (" + logger.Syslog.DestinationHost + ":" + CStringHelper::Safe_IntToAscii(logger.Syslog.DestinationPort) + ")";
		}
	}
#endif

	return "";
}

void CFirewall::SetLoggerFields()
{
	//set logger fields
	CStringList fields;
	fields.AddTail("Date");
	fields.AddTail("Time");
	fields.AddTail("Site Instance");
	fields.AddTail("Event");
	if(Settings.Logging.LogUserName) fields.AddTail("Username");
	fields.AddTail("Additional info about request (event specific)");
	logger.SetHeaderFields(fields);
}

bool CFirewall::UpdateSettings(bool force)
{
	if (UpdateStamp.IsTriggered() || force){
		if (Settings.Update(force)){	//run-time update or force
			SetLoggerFields(); //update logger header
			LoadCache();
			CFileName fnLoaded = Settings.GetLoadedSettingsFileName();
			Settings.WriteToFile(fnLoaded.FullPath);//write loaded settings to a debug file
			if(force){
				Message("INFO: Reload done of settings!");
			}else{
				Message("INFO: Detected change in settings, reload done!");
			}
			Message("INFO: You can have a look at the currently loaded settings in the file '" + fnLoaded.FileName + "'.");
			return true;
		}
	}
	return false;
}

void CFirewall::SaveRunningValues(CString &Path, LPCTSTR FileName)
{
	//write loaded settings to a file (debug/additional check)
	if(Settings.WriteToFile(Path + FileName))
		Message("INFO: To check if loaded correctly, you can have a look at the currently loaded settings in the file '" + CString(FileName) + "' (start config.exe and open this file).");
}

void CFirewall::WarnLogonlyMode()
{
	//are we in logging only mode? if so, warning!
	if(Settings.Response.LogOnly)
		Warning("Firewall is in logging only mode! Nothing will be blocked!");
}

void CFirewall::Alert(const CString& Message, const int LogType)
{
	if(Settings.Response.LogOnly){
		logger.Append("ALERT: " + Message);
	}else{
		switch(LogType){
			case Action::Disabled:	logger.Append("ALERT: " + Message);			break;
			case Action::Block:		logger.Append("BLOCKED: " + Message);		break;
			case Action::Monitor:	logger.Append("MONITORED: " + Message);		break;
			case Action::BlockIP:	logger.Append("BLOCKED: " + Message);		break;
			case Action::MonitorIP:	logger.Append("MONITORED: " + Message);		break;
			default:				logger.Append("ALERT: " + Message);			break;
		}
	}
	Settings.Statistics.Alerts.Add(const_cast<CString&>(Message));
}

void CFirewall::Message(const CString& Message)
{
	logger.NewEntryFlush(Message);
	Settings.Statistics.Messages.Add(const_cast<CString&>(Message));
}

void CFirewall::Warning(const CString& Message)
{
	logger.NewEntryFlush("WARNING: " + Message);
	Settings.Statistics.Messages.Add(const_cast<CString&>(Message));
}

void CFirewall::LoadCache()
{
	Settings.Statistics.Alerts.SetMaxAge(CTimeSpan(0,24,0,0));//in hours.
	Settings.Statistics.Alerts.SetMaxItems(1000);

	Settings.Statistics.Messages.SetMaxAge(CTimeSpan(0,24,0,0));//in hours.
	Settings.Statistics.Messages.SetMaxItems(1000);
}