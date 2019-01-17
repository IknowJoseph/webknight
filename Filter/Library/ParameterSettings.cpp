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
#include "StdAfx.h"
#include "ParameterSettings.h"

CParameterSettings::CParameterSettings(void)
{
	LoadDefaults();
}

CParameterSettings::~CParameterSettings(void)
{
}

void CParameterSettings::Init()
{
	Query.Init();
	Post.Init();
	Cookie.Init();
}

void CParameterSettings::Clear()
{
	Query.Cache.Clear();
	Post.Cache.Clear();
	Cookie.Cache.Clear();
}

void CParameterSettings::LoadDefaults()
{
	Query.AllowNotInList = true;
	Query.IgnoreCase = true;
	Post.AllowNotInList = true;
	Post.IgnoreCase = true;
	Cookie.AllowNotInList = true;
	Cookie.IgnoreCase = true;

	Validation.LoadDefaults();
}

bool CParameterSettings::ApplyConstraints()
{
	CSettings::ApplyConstraints();

	Query.ApplyConstraints();
	Post.ApplyConstraints();
	Cookie.ApplyConstraints();

	return true;
}

bool CParameterSettings::ReadFromFileINI(LPCTSTR fn)
{
	return false;
}

bool CParameterSettings::WriteToFileINI(LPCSTR fn)
{
	return false;
}

bool CParameterSettings::WriteToFileXML(LPCTSTR fn)
{
	CString xml("");

	//xml += "<!DOCTYPE WebApplicationParameters[\r\n";			//start dtd
	//xml += "<!ELEMENT WebApplicationParameters ANY >\r\n";
	//xml += " ]>\r\n";							//end dtd

	xml += "<WebApplicationParameters Version='" + Safe_DoubleToAscii(Version) + "'>\r\n";	//start entity
	xml += "<Web_Application_Parameters App='Document'/>\r\n";
	xml += "<Web_Application_Parameters App='Title'/>\r\n";
	xml += ToXML();
	xml += "</WebApplicationParameters>\r\n";		//end entity
	
	return XML.WriteEntityToFile(fn,xml);
}

bool CParameterSettings::ParseXML(CString &key, CString &val)
{
	//if not a valid key
	if (key=="")
		return false;

	CString name = CXML::Decode(CXML::TagName(key));

	PARSE_XML_CMAPSTRINGTOSTRING(Query,Validators,"Query_Validators")
	else PARSE_XML_CMAPSTRINGTOSTRING(Post,Validators,"Post_Validators")
	else PARSE_XML_CMAPSTRINGTOSTRING(Cookie,Validators,"Cookie_Validators")

	else PARSE_XML_CMAPSTRINGTOSTRING(Query,MaxLength,"Query_Max_Length")
	else PARSE_XML_CMAPSTRINGTOSTRING(Post,MaxLength,"Post_Max_Length")
	else PARSE_XML_CMAPSTRINGTOSTRING(Cookie,MaxLength,"Cookie_Max_Length")

	else PARSE_XML_BOOL(Query,AllowNotInList,"Query_Allow_Not_In_List")
	else PARSE_XML_BOOL(Post,AllowNotInList,"Post_Allow_Not_In_List")
	else PARSE_XML_BOOL(Cookie,AllowNotInList,"Cookie_Allow_Not_In_List")

	else PARSE_XML_BOOL(Query,IgnoreCase,"Query_Ignore_Case")
	else PARSE_XML_BOOL(Post,IgnoreCase,"Post_Ignore_Case")
	else PARSE_XML_BOOL(Cookie,IgnoreCase,"Cookie_Ignore_Case")

	else PARSE_XML_CMAPSTRINGTOSTRING(Validation,Patterns,"Validation_Patterns")
	else PARSE_XML_CSTRINGLIST(Validation,Order,"Validation_Detection")

	else{
		return false;	//not parsed
	}
	return true;
}

CString CParameterSettings::ToXML()
{
	CString xml("");
#define PARAMETERS_GETXML(name, parameter) \
	xml += XML.AddSeparator(#name##); \
	xml += XML.ToXML(#name ## "_Validators",##name.Validators,"Key is the " #parameter## " name and value is the validator or regex pattern to use."); \
	xml += XML.ToXML(#name ## "_Max_Length",##name.MaxLength,"Optionally restrict the length of " #parameter## "s. Key is the " #parameter## " name and value is the maximum length of the " #parameter## " value."); \
	xml += XML.ToXML(#name##"_Allow_Not_In_List","Option",##name.AllowNotInList?"1":"0","1","Allows unmatched validator " #parameter## "s in the request."); \
	xml += XML.ToXML(#name##"_Ignore_Case","Option",##name.IgnoreCase?"1":"0","1","Ignore case of " #parameter## " names when applying validators. When this is disabled, it is recommended to disable Allow Not In List (to prevent bypassing the validators).");

	PARAMETERS_GETXML(Query, parameter)
	PARAMETERS_GETXML(Post, parameter)
	PARAMETERS_GETXML(Cookie, parameter)

	xml += XML.AddSeparator("Validation");
	xml += XML.ToXML("Validation_Patterns",Validation.Patterns,"The regular expressions used to validate user input.");
	xml += XML.ToXML("Validation_Detection",Validation.Order,"These are the validators used to automatically detect the parameter type in this exact order. Should be from least allowing to most allowing validator.");

	return xml;
}