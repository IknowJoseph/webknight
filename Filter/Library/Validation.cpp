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
#include "StdAfx.h"
#include "Validation.h"

CValidation::CValidation(void)
{
}

CValidation::~CValidation(void)
{
}

CString CValidation::MatchPattern(CString& data)
{
	CString index;
	CString validatorName;
	CString validatorPattern;
	POSITION pos = Validation.Order.GetHeadPosition();
	while(pos!=NULL){
		validatorName = Validation.Order.GetNext(pos);
		if(Validation.Patterns.Lookup(validatorName,validatorPattern)){
			CAtlRegExp<>* regex = Regex.Lookup(validatorPattern);
			if(regex!=NULL){ //NULL = regex syntax error
				CAtlREMatchContext<> mc;
				if(regex->Match(data,&mc)){
					return validatorName;
				}
			}
		}
	}
	return "";
}

bool CValidation::Validate(WebParam& Parameters, CString& name, CString& value)
{
	if(Parameters.IgnoreCase)
		CStringHelper::Safe_MakeLower(name);

	CString validatorName;
	CString validatorPattern;
	if(Parameters.Validators.Lookup(name,validatorName)){

		if(!Validation.Patterns.Lookup(validatorName,validatorPattern))
			validatorPattern = validatorName; //use validator as regex pattern instead of name of validator

		CAtlRegExp<>* regex = Regex.Lookup(validatorPattern);
		if(regex!=NULL){ //NULL = regex syntax error
			CAtlREMatchContext<> mc;
			return (regex->Match(value,&mc) == TRUE /* to avoid warning */ && Validate(Parameters,name,value.GetLength()));
		}
	}

	return Validate(Parameters,name,value.GetLength()) && Parameters.AllowNotInList;
}

bool CValidation::Validate(WebParam& Parameters, CString& name, int length)
{
	CString size;
	if(Parameters.MaxLength.Lookup(name,size))
		return !(length>atol(size));

	return true;
}

bool CValidation::HasValidator(WebParam& Parameters, CString name)
{
	LPCTSTR key;
	if(Parameters.Validators.LookupKey(name,key))
		return true;

	CStringHelper::Safe_MakeLower(name);

	if(Parameters.Validators.LookupKey(name,key))
		return true;

	return false;
}
