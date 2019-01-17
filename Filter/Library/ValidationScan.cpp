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
#include "ValidationScan.h"
#include "URL.h"

CValidationScan::CValidationScan(void)
{
	isPHP = false;
	removeLeadingSpace = false;
	nameValidator = NULL;
	inputValidation = NULL;
	scanPollution = false;
	pSessions = NULL;
}

CValidationScan::~CValidationScan(void)
{
}

void CValidationScan::Scan(CString key, CString val, WebParam& Parameters)
{
	if(removeLeadingSpace)
		key = key.TrimLeft(); //for Cookie "par1=a; par2=b" and PHP

	if(pSessions && IsSessionID(key)){
		CString session = key + '=' + val;
		CStringHelper::Safe_MakeUpper(session);
		pSessions->AddTail(session);
	}

	if(nameValidator!=NULL){ //NULL = regex syntax error or no validation required
		CAtlREMatchContext<> mc;
		if(!nameValidator->Match(key,&mc)){
			result.badParameters.AddTail(key);
		}
	}

	if(isPHP)
		CleanPHPKey(key);

	if(inputValidation){

		if(!Parameters.Cache.IsFull()){
			if(!Parameters.Cache.Exists(key) && !inputValidation->HasValidator(Parameters,key)){
				Parameters.Cache.Add(key,inputValidation->MatchPattern(val));
			}
		}

		if(!inputValidation->Validate(Parameters,key,val)){
			result.failedParameters.AddTail(key);
		}
	}
	//WARNING: function Validate might have changed key to lowercase

	if(scanPollution){

		//ASP parameters are case insensitive
		//always case insensitive compare
		if(IsInListCompareNoCase(key,result.parameters)){
			result.pollutedParameters.AddTail(key);
		}else{
			result.parameters.AddTail(key);
		}
	}

}

void CValidationScan::Scan(CString& Data, TCHAR TokenKey, TCHAR TokenValue, WebParam& Parameters)
{
	TCHAR c;
	CString key = "";
	CString val = "";
	bool isKey = true;
	bool valid = false;
	int length = Data.GetLength();

	for(int i=0; i<length+1; i++){
		if(i==length)
			c = TokenKey;
		else
			c = Data.GetAt(i);

		if(c==TokenKey){
			if(key.GetLength()>0){
				key = CURL::Decode(key);
				val = CURL::Decode(val);
				Scan(key,val,Parameters);
			}
			key = "";
			val = "";
			isKey = true;
		}else if(c==TokenValue){
			if(isKey)
				isKey = false;
			else
				val += c;
		}else{
			if(isKey)
				key += c;
			else
				val += c;
		}
	}
}

inline bool CFormProcessor::IsSessionID(CString key)
{
	CStringHelper::Safe_MakeUpper(key);
	return key.Find("SESSIONID")>-1 || key.Find("PHPSESSID")>-1;
}

inline void CFormProcessor::CleanPHPKey(CString& key)
{
	//PHP removes leading spaces and replaces dots, whitespaces and open brackets with underscores
	//key = key.TrimLeft(); //already done above
	key.Replace(' ','_');
	key.Replace('.','_');
	key.Replace('[','_');
	for(unsigned char c=128; c<160; c++)
		key.Replace(c,'_');
}
