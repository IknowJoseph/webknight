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
#include "HeaderValidation.h"

CHeaderValidation::CHeaderValidation(void)
{
	LoadDefaults();
}

CHeaderValidation::~CHeaderValidation(void)
{
}

void CHeaderValidation::Init()
{
	Headers.Init(14*24, 100);
}

void CHeaderValidation::Clear()
{
	Headers.Cache.Clear();
}

void CHeaderValidation::LoadDefaults()
{
	Headers.AllowNotInList = true;
	Headers.IgnoreCase = true;
	Validation.LoadDefaults();
}

bool CHeaderValidation::ApplyConstraints()
{
	CSettings::ApplyConstraints();

	Headers.ApplyConstraints();

	return true;
}

bool CHeaderValidation::ReadFromFileINI(LPCTSTR fn)
{
	return false;
}

bool CHeaderValidation::WriteToFileINI(LPCSTR fn)
{
	return false;
}

bool CHeaderValidation::WriteToFileXML(LPCTSTR fn)
{
	CString xml("");

	//xml += "<!DOCTYPE HeaderValidation[\r\n";			//start dtd
	//xml += "<!ELEMENT HeaderValidation ANY >\r\n";
	//xml += " ]>\r\n";							//end dtd

	xml += "<HeaderValidation Version='" + Safe_DoubleToAscii(Version) + "'>\r\n";	//start entity
	xml += "<Header_Validation App='Document'/>\r\n";
	xml += "<Header_Validation App='Title'/>\r\n";
	xml += ToXML();
	xml += "</HeaderValidation>\r\n";		//end entity
	
	return XML.WriteEntityToFile(fn,xml);
}

bool CHeaderValidation::ParseXML(CString &key, CString &val)
{
	//if not a valid key
	if (key=="")
		return false;

	CString name = CXML::Decode(CXML::TagName(key));

	PARSE_XML_CMAPSTRINGTOSTRING(Headers,Validators,"Headers_Validators")
	else PARSE_XML_CMAPSTRINGTOSTRING(Headers,MaxLength,"Headers_Max_Length")
	else PARSE_XML_BOOL(Headers,AllowNotInList,"Headers_Allow_Not_In_List")
	else PARSE_XML_BOOL(Headers,IgnoreCase,"Headers_Ignore_Case")

	else PARSE_XML_CMAPSTRINGTOSTRING(Validation,Patterns,"Validation_Patterns")
	else PARSE_XML_CSTRINGLIST(Validation,Order,"Validation_Detection")

	else{
		return false;	//not parsed
	}
	return true;
}

CString CHeaderValidation::ToXML()
{
	CString xml("");
	CHeaderValidation d;
#define PARAMETERS_GETXML(name, parameter) \
	xml += XML.AddSeparator(#name##); \
	xml += XML.ToXML(#name ## "_Validators",##name.Validators,"Key is the " #parameter## " name and value is the validator or regex pattern to use."); \
	xml += XML.ToXML(#name ## "_Max_Length",##name.MaxLength,"Optionally restrict the length of " #parameter## "s. Key is the " #parameter## " name and value is the maximum length of the " #parameter## " value."); \
	xml += XML.ToXML(#name##"_Allow_Not_In_List","Option",##name.AllowNotInList?"1":"0",d.##name.AllowNotInList?"1":"0","Allows unmatched validator " #parameter## "s in the request."); \
	xml += XML.ToXML(#name##"_Ignore_Case","Option",##name.IgnoreCase?"1":"0",d.##name.IgnoreCase?"1":"0","Ignore case of " #parameter## " names when applying validators. When this is disabled, it is recommended to disable Allow Not In List (to prevent bypassing the validators).");

	PARAMETERS_GETXML(Headers, header)

	xml += XML.AddSeparator("Validation");
	xml += XML.ToXML("Validation_Patterns",Validation.Patterns,"The regular expressions used to validate user input.");
	xml += XML.ToXML("Validation_Detection",Validation.Order,"These are the validators used to automatically detect the parameter type in this exact order. Should be from least allowing to most allowing validator.");

	return xml;
}

bool CHeaderValidation::Validate(WebParam& Parameters, CString& name, CString& value)
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
			if(regex->Match(value,&mc) == FALSE){
				//split header values when not matched or in regex pattern
				CStringList fields;
				CStringHelper::Split(fields,value,", ",20);
				POSITION pos = fields.GetHeadPosition();
				while(pos!=NULL){
					if(regex->Match(fields.GetNext(pos),&mc)==FALSE)
						return false;
				}
			}
			return CValidation::Validate(Parameters,name,value.GetLength());
		}
	}

	return CValidation::Validate(Parameters,name,value.GetLength()) && Parameters.AllowNotInList;
}
