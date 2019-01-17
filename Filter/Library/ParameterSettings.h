/*
    AQTRONIX C++ Library
    Copyright 2015-2016 Parcifal Aertssen

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

#include "Settings.h"
#include "Validation.h"

class RuleParameters{
public:
	Rule Pollution;
	RuleString NameRequireRegex;
	Rule InputValidation;
};

class CParameterSettings : public CSettings, public CValidation
{
public:
	WebParam Query;
	WebParam Post;
	WebParam Cookie;

	CString ToXML();
	bool ParseXML(CString& key, CString& val);
	bool WriteToFileINI(LPCSTR fn);
	bool ReadFromFileINI(LPCTSTR fn);
	bool WriteToFileXML(LPCTSTR fn);
	void LoadDefaults();
	bool ApplyConstraints();

	void Init();
	void Clear();

	CParameterSettings(void);
	virtual ~CParameterSettings(void);
};
