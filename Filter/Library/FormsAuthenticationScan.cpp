/*
    AQTRONIX C++ Library
    Copyright 2018 Parcifal Aertssen

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
#include "StdAfx.h"
#include "FormsAuthenticationScan.h"
#include "URL.h"
#include "StringHelper.h"

CFormsAuthenticationScan::CFormsAuthenticationScan(void)
{
	User = "";
	Pass = "";
	HasPass = false;
	IsUsernamePolluted = false;
	IsPasswordPolluted = false;
}

CFormsAuthenticationScan::~CFormsAuthenticationScan(void)
{
}

void CFormsAuthenticationScan::Scan(CString key, CString val, CStringList& UsernameFields, CStringList& PasswordFields)
{
	if(removeLeadingSpace)
		key = key.TrimLeft();

	if(isPHP)
		CleanPHPKey(key);

	if(CStringHelper::IsInListCompareNoCase(key,UsernameFields)){
		if(User==""){
			User = val;
		}else{
			IsUsernamePolluted = true;
			User += "," + val;
		}
	}else if(CStringHelper::IsInListCompareNoCase(key,PasswordFields)){
		if(Pass==""){
			Pass = val;
			HasPass = true;
		}else{
			IsPasswordPolluted = true;
			Pass += "," + val;
		}
	}
}

void CFormsAuthenticationScan::Scan(CString& Data, CStringList& UsernameFields, CStringList& PasswordFields)
{
	int length = Data.GetLength();
	if(length>0){
		TCHAR c;
		CString key = "";
		CString val = "";
		bool isVal = false;
		for(int i=0; i<length+1; i++){
			if(i==length)
				c = '&';
			else
				c = Data.GetAt(i);

			if(c=='&'){
				key = CURL::Decode(key);
				val = CURL::Decode(val);
				Scan(key,val,UsernameFields,PasswordFields);

				val = "";
				key = "";
				isVal = false;
			}else if(c=='='){
				isVal = true;
			}else{
				if(isVal)
					val += c;
				else
					key += c;
			}
		}
	}
}
