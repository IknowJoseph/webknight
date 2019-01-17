/*
    AQTRONIX C++ Library
    Copyright 2016 Parcifal Aertssen

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
#pragma once
#include "settings.h"
#include "StringCache.h"
#include "Action.h"

class CExperimentalSettings :
	public CSettings
{
public:

	class _UserAgent {
	public:
		Rule Anomalies;
		int AnomaliesThreshold;
		bool AnomaliesLogRequest;
		CStringCache UA;
		CStringList Browsers;
		CStringList FromBots;
		CStringList Ignore;
	} UserAgent;

	class _Headers {
	public:
		Rule InputValidation;
		bool LogNewHeaders;
		CStringCache ValidationFailures;
		bool LogValidationFailures;
		RuleString NameRequireRegex;
	} Headers;

	class _Session {
	public:
		int Timeout;
		Rule Lock;
		bool ByIP;
		bool ByUserAgent;
		_StringList Excluded;
	} Session;

	class _Post {
	public:
		bool ScanDataUrl;
	} Post;

	CString ToXML();
	bool ParseXML(CString& key, CString& val);
	bool WriteToFileINI(LPCSTR fn);
	bool ReadFromFileINI(LPCTSTR fn);
	bool WriteToFileXML(LPCTSTR fn);
	void LoadDefaults();
	bool ApplyConstraints();

	void Enable();

	CExperimentalSettings(void);
	virtual ~CExperimentalSettings(void);
};
