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

#include "StringHelper.h"
#include "StringCache.h"
#include "RegexCache.h"

class WebParam{
public:
	CStringCache Cache;
	bool AllowNotInList;
	bool IgnoreCase;
	CMapStringToString Validators;
	CMapStringToString MaxLength;

	void Init(int hours = 72, unsigned int maxitems = 10)
	{
		Cache.SetMaxItems(maxitems);
		Cache.SetMaxAge(CTimeSpan(0,hours,0,0));
	}

	void ApplyConstraints()
	{
		if(IgnoreCase){
			ApplyIgnoreCase(Validators);
			ApplyIgnoreCase(MaxLength);
		}
	}

private:
	void ApplyIgnoreCase(CMapStringToString& map)
	{
		CMapStringToString convert;
		CString key;
		CString val;
		POSITION pos = map.GetStartPosition();
		while(pos!=NULL){
			map.GetNextAssoc(pos,key,val);
			CStringHelper::Safe_MakeLower(key);
			convert.SetAt(key,val);
		}
		CStringHelper::Copy(convert,map,true);
	}
};

class ValidationParam{
public:
	CMapStringToString Patterns;
	CStringList Order;

	void Add(LPCTSTR Name, LPCTSTR Pattern)
	{
		Patterns.SetAt(Name,Pattern);
		Order.AddTail(Name);
	}

	void LoadDefaults()
	{
		//VALIDATORS: order has to be from least allowing to most allowing for auto detection

		//Numeric
		Add(_T("Empty"),_T("^$"));
		Add(_T("Boolean"),_T("^[01]$"));
		Add(_T("Identity"),_T("^[0-9]+$"));
		Add(_T("Number"),_T("^[+\\-]?[0-9]*$"));
		Add(_T("Hexadecimal"),_T("^\\h*$"));
		Add(_T("Guid"),_T("^\\h\\h\\h\\h\\h\\h\\h\\h-\\h\\h\\h\\h-\\h\\h\\h\\h-\\h\\h\\h\\h-\\h\\h\\h\\h\\h\\h\\h\\h\\h\\h\\h\\h$"));
		Add(_T("Float"),_T("^[0-9]+[\\.,][0-9]+$"));
		Add(_T("Dot-decimal"),_T("^[0-9\\.]*$"));
		Add(_T("Range"),_T("^\\d+-\\d+$"));

		//Datetime
		Add(_T("Time"),_T("^\\d\\d:\\d\\d(:\\d\\d(\\.\\d\\d\\d)?)?$"));
		Add(_T("Date"),_T("^\\d\\d?[/\\-]\\d\\d?[/\\-]\\d\\d\\d?\\d?$"));
		Add(_T("ISO Date"),_T("^\\d\\d\\d\\d-?\\d\\d-?\\d\\d$"));
		Add(_T("Datetime"),_T("^\\d\\d\\d\\d-\\d\\d-\\d\\d( |[A-Z])\\d\\d:\\d\\d(:\\d\\d(\\.\\d\\d\\d)?)?$"));
		Add(_T("Http Date"),_T("^((Sun)|(Mon)|(Tue)|(Wed)|(Thu)|(Fri)|(Sat)), \\d\\d \\c\\c\\c \\d\\d\\d\\d \\d\\d:\\d\\d:\\d\\d GMT$")); //rfc 1123

		//String
		Add(_T("Yes/No"),_T("^((Y|y(es)?)|(N|n(o)?))$"));
		Add(_T("True/False"),_T("^(T|t(rue)?)|(F|f(alse)?)$"));
		Add(_T("On/Off"),_T("^(O|on)|(O|off)$"));
		Add(_T("Enabled/Disabled"),_T("^(E|en)|(D|dis)abled$"));
		Add(_T("Order"),_T("^((([Aa])|([Dd][Ee]))[Ss][Cc])?$"));
		Add(_T("Character"),_T("^.?$"));
		Add(_T("Alphabetic"),_T("^\\c*$"));
		Add(_T("Alphanumeric"),_T("^\\a*$"));
		Add(_T("Alphanumeric List"),_T("^((\\a+[,;]\\b?)*\\a+)?$"));
		Add(_T("Word"),_T("^[a-zA-Z0-9\\-]*$"));
		Add(_T("Word List"),_T("^(([a-zA-Z0-9\\-]+[,;]\\b?)*[a-zA-Z0-9\\-]+)?$"));
		Add(_T("Sentence"),_T("^(([a-zA-Z0-9\\-,]+\\b)*[a-zA-Z0-9\\-]+[.\\!\\?]?)?$"));
		Add(_T("Filename"),_T("^[a-zA-Z0-9_\\.\\-]*$"));
		Add(_T("Hostname"),_T("^((([a-zA-Z0-9\\-]+\\.)*[a-zA-Z0-9\\-]*)|(\\[([0-9a-fA-F:.])+\\]))$"));
		Add(_T("Path"),_T("^[a-zA-Z0-9_\\.\\-/]*$"));
		Add(_T("Windows Path"),_T("^(\\c:)?[a-zA-Z0-9_\\.\\-\\\\]*$"));
		Add(_T("E-mail"),_T("^([a-zA-Z0-9\\._%\\+\\-]+@([a-zA-Z0-9\\-]+\\.)+[a-zA-Z\\-]+)?$"));
		Add(_T("Http Url"),_T("^(https?://.+)?$"));
		Add(_T("Uri"),_T("^([a-zA-Z]([a-zA-Z0-9\\-\\+\\.])*://.+)?$"));
		Add(_T("Base64"),_T("^([a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/])*(([a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/]==)|([a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/][a-zA-Z0-9\\+\\/]=))?$"));
		Add(_T("Quoted Text"),_T("^\\q$"));
		Add(_T("Text"),_T("^.*$"));

		//not automatically detected (after Text)
		Add(_T("No Quotes"),_T("^[^\\\"\\']*$"));
		Add(_T("No Quotes And Tags"),_T("^[^\\\"\\'<>]*$"));
		Add(_T("No Tags"),_T("^[^<>]*$"));
	}
};

class CValidation
{
public:
	ValidationParam Validation;
	CRegexCache Regex;

public:
	CString MatchPattern(CString& data);
	virtual bool Validate(WebParam& Parameters, CString& name, CString& value);
	virtual bool Validate(WebParam& Parameters, CString& name, int length);
	bool HasValidator(WebParam& Parameters, CString name);

	CValidation(void);
	virtual ~CValidation(void);
};