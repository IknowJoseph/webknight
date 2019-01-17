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
// Firewall.h: interface for the CFirewall class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_FIREWALL_H__5FDE31D9_F12E_462C_8BBE_017827550E3C__INCLUDED_)
#define AFX_FIREWALL_H__5FDE31D9_F12E_462C_8BBE_017827550E3C__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "ExploitScan.h"
#include "ProcessHelper.h"
#include "Logger.h"
#include "FirewallSettings.h"
#include "RegexCache.h"

class CFirewall : public CExploitScan  
{
public:
	virtual void LoadCache();
	virtual void ClearCache();
	virtual void Alert(const CString& Message, const int LogType = 1);
	virtual void Message(const CString& Message);
	virtual void Warning(const CString& Message);
	virtual void WarnLogonlyMode();
	virtual void SaveRunningValues(CString& Path, LPCTSTR FileName);
	virtual bool UpdateSettings(bool force = false);
	virtual void SetLoggerFields();
	virtual CString InitializeLogger(LPCTSTR DefaultLogFolder, LPCTSTR SoftwareHeader, LPCTSTR Suffix = NULL);
	virtual CString SaveDefaultSettingFile(CString& Path, LPCTSTR SettingFile);
	virtual CString LoadSettingFile(CString& Path, LPCTSTR SettingFile, LPCTSTR BackupFile1 = NULL, LPCTSTR BackupFile2 = NULL);

	bool DenyChar(const char* p, char c, const char* LogMsg, const int LogType = 1);
	bool DenyChar(const char* p, char c, const char* LogMsg, CStringList& Log);
	bool DenyMultipleCharacters(CString& ScanString, char c, const char* LogMsg, const int LogType = 1);
	bool DenyString(const char* p, const char* pStr, const char* LogMsg, const int LogType = 1);
	bool DenyString(const char* p, const char* pStr, const char* LogMsg, CStringList& List);//List
	bool DenySequences(CString& ScanString, CStringList& Sequences, CString LogPre, CString LogPost, const int LogType = 1);//String
	bool DenySequences(CString& ScanString, CStringList& Sequences, CString LogPre, CString LogPost, CStringList& Log);//String Log
	bool DenySequences(CString& ScanString1, CString& ScanString2, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType = 1);//String String
	bool DenySequences(CString& ScanString1, CString& ScanString2, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log);//String String Log
	bool DenySequences(CStringList &ScanList, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType = 1);	//List
	bool DenySequences(CStringList &ScanList, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log); //List Log
	bool DenySequences(CStringList &ScanList1, CStringList& ScanList2, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType = 1);//List List
	bool DenySequences(CStringList &ScanList1, CStringList& ScanList2, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log); //List List Log
	
	int DenyCharactersCount(CString& ScanString, CString& Characters, CString LogPre, CString LogPost, const int LogType = 1);//String
	int DenyCharactersCount(CString& ScanString, CString& Characters, CString LogPre, CString LogPost, CStringList& Log);//String Log
	int DenyCharactersCount(CString& ScanString1, CString& ScanString2, CString& Characters, CString LogPre, CString LogPost, const int LogType = 1);//String String
	int DenyCharactersCount(CString& ScanString1, CString& ScanString2, CString& Characters, CString LogPre, CString LogPost, CStringList& Log);//String String Log

	int DenySequencesCount(CString& ScanString, CStringList& Sequences, CString LogPre, CString LogPost, const int LogType = 1);//String Log
	int DenySequencesCount(CString& ScanString, CStringList& Sequences, CString LogPre, CString LogPost, CStringList& Log);//String Log
	int DenySequencesCount(CString& ScanString1, CString& ScanString2, CStringList& Sequences, CString LogPre, CString LogPost, const int LogType = 1);//String String
	int DenySequencesCount(CString& ScanString1, CString& ScanString2, CStringList& Sequences, CString LogPre, CString LogPost, CStringList& Log);//String String Log
	int DenySequencesCount(CStringList &ScanList, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType = 1); //List
	int DenySequencesCount(CStringList &ScanList, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log); //List Log
	int DenySequencesCount(CStringList &ScanList1, CStringList& ScanList2, CStringList &Sequences, CString LogPre, CString LogPost, const int LogType = 1); //List List
	int DenySequencesCount(CStringList &ScanList1, CStringList& ScanList2, CStringList &Sequences, CString LogPre, CString LogPost, CStringList& Log); //List List Log

	bool DenySpecialWhitespace(LPCTSTR Text, CString AppendText, const int LogType = 1);
	bool DenyRegex(CString& Data, CMapStringToString& Patterns,CString LogPre, CString LogPost, const int LogType = 1);

	CFirewall(CFirewallSettings& _Settings, CLogger& _logger);
	virtual ~CFirewall();

public:
	CLogger& logger;
	CFirewallSettings& Settings;

protected:
	class _UpdateStamp {
	public:
		CTime Time;

		void Init(){
			_tzset();
			Time = CTime::GetCurrentTime();
		}

		bool IsTriggered(){
			//if enough time passed (every 1 minute)
			_tzset();
			CTime now = CTime::GetCurrentTime();
			if(now-Time>CTimeSpan(60)){
				//set time last update
				Time = now;
				return true;
			}
			return false;
		}

	} UpdateStamp;
};


#endif // !defined(AFX_FIREWALL_H__5FDE31D9_F12E_462C_8BBE_017827550E3C__INCLUDED_)
