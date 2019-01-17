/*
    AQTRONIX C++ Library
    Copyright 2003-2016 Parcifal Aertssen

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
// Settings.h: interface for the CSettings class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_SETTINGS_H__270445F3_48E4_49D3_8EAF_CAB52E330BF9__INCLUDED_)
#define AFX_SETTINGS_H__270445F3_48E4_49D3_8EAF_CAB52E330BF9__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "FileName.h"
#include "FileStamp.h"
#include "XML.h"
#include "StringHelper.h"
#include <afxmt.h>		// for synchronization objects

#define SETTINGS_MAX_XML_FILE			10240000
#define SETTINGS_MAX_INI_BUF_SIZE		65536

typedef int Rule;
#define RULE_SELECTION "Display='Disabled;Block;Monitor;Block IP;Monitor IP'"

#define READ_INI_RULE(location,var) \
		;##location.##var = GetPrivateProfileInt(#location,#var,##location.##var,fn);

#define READ_INI_BOOL(location,var) \
		;##location.##var = GetPrivateProfileInt(#location,#var,##location.##var,fn)>0;

#define READ_INI_RULE_INT(location,var) \
		;##location.##var.Action = GetPrivateProfileInt(#location,#var ".Action",##location.##var.Action,fn)\
		;##location.##var.Value = GetPrivateProfileInt(#location,#var ".Value",##location.##var.Value,fn);

#define READ_INI_INT(location,var) \
		;##location.##var = GetPrivateProfileInt(#location,#var,##location.##var,fn);

//#define READ_INI_LONG(location,var) \
//		GetPrivateProfileString(#location,#var,Safe_LongToAscii(##location.##var),buf,sz,fn) \
//		;##location.##var = atol(buf); \

#define READ_INI_RULE_STRING(location,var) \
		GetPrivateProfileString(#location,#var ".Value",##location.##var.Value,buf,sz,fn) \
		;##location.##var.Value = buf; INI.Cleanup(##location.##var.Value) \
		;##location.##var.Action = GetPrivateProfileInt(#location,#var ".Action",##location.##var.Action,fn);

#define READ_INI_RULE_CHARACTERS(location,var) \
		READ_INI_RULE_STRING(location,var)

#define READ_INI_STRING(location,var) \
		GetPrivateProfileString(#location,#var,##location.##var,buf,sz,fn) \
		;##location.##var = buf; INI.Cleanup(##location.##var); \

//#define READ_INI_STRING(location,var) \
//		{ CString strini(##location.##var); \
//		GetPrivateProfileString(#location,#var,"",buf,sz,fn) \
//		;##location.##var = buf; INI.Cleanup(##location.##var); \
//		if(##location.##var==""){##location.##var=strini;}}

#define READ_INI_CSTRINGLIST(location,var,cleanup) \
		l = GetPrivateProfileSection(#location "." #var,buf,sz,fn);\
		Split(buf,l,##location.##var)\
		;##cleanup(##location.##var);

#define READ_INI_LIST(location,var,cleanup)\
		;##location.##var.Enabled = GetPrivateProfileInt(#location,#var,##location.##var.Enabled,fn)>0;\
		l = GetPrivateProfileSection(#location "." #var,buf,sz,fn);\
		Split(buf,l,##location.##var.List)\
		;##cleanup(##location.##var.List);

#define READ_INI_RULE_LIST(location,var,cleanup)\
		;##location.##var.Action = GetPrivateProfileInt(#location,#var,##location.##var.Action,fn);\
		l = GetPrivateProfileSection(#location "." #var,buf,sz,fn);\
		Split(buf,l,##location.##var.List)\
		;##cleanup(##location.##var.List);

#define READ_INI_MAP(location,var,cleanup)\
		;##location.##var.Enabled = GetPrivateProfileInt(#location,#var,##location.##var.Enabled,fn)>0;\
		l = GetPrivateProfileSection(#location "." #var,buf,sz,fn);\
		if(l>0){\
			CStringList list;\
			Split(buf,l,list)\
			;##cleanup(list)\
			;##location.##var.Map.RemoveAll();\
			Split(list,'=',##location.##var.Map);\
		}

#define READ_INI_RULE_MAP(location,var,cleanup)\
		;##location.##var.Action = GetPrivateProfileInt(#location,#var,##location.##var.Action,fn);\
		l = GetPrivateProfileSection(#location "." #var,buf,sz,fn);\
		if(l>0){\
			CStringList list;\
			Split(buf,l,list)\
			;##cleanup(list)\
			;##location.##var.Map.RemoveAll();\
			Split(list,'=',##location.##var.Map);\
		}

#define READ_INI_RULE_CACHE(location,var) \
		;##location.##var.Action = GetPrivateProfileInt(#location,#var ".Action",##location.##var.Action,fn)\
		;##location.##var.MaxCount = GetPrivateProfileInt(#location,#var ".MaxCount",##location.##var.MaxCount,fn)\
		;##location.##var.MaxTime = GetPrivateProfileInt(#location,#var ".MaxTime",##location.##var.MaxTime,fn);

#define READ_INI_CACHE(location,var) \
		;##location.##var.Enabled = GetPrivateProfileInt(#location,#var ".Enabled",##location.##var.Enabled,fn)>0\
		;##location.##var.MaxCount = GetPrivateProfileInt(#location,#var ".MaxCount",##location.##var.MaxCount,fn)\
		;##location.##var.MaxTime = GetPrivateProfileInt(#location,#var ".MaxTime",##location.##var.MaxTime,fn);

#define WRITE_INI_RULE(location,var) \
	WritePrivateProfileString(#location,#var,Safe_IntToAscii(##location.##var),fn);
#define WRITE_INI_BOOL(location,var) \
	WritePrivateProfileString(#location,#var,##location.##var?"1":"0",fn);
#define WRITE_INI_RULE_INT(location,var) \
	WritePrivateProfileString(#location,#var ".Action",Safe_IntToAscii(##location.##var.Action),fn);\
	WritePrivateProfileString(#location,#var ".Value",Safe_IntToAscii(##location.##var.Value),fn);
#define WRITE_INI_INT(location,var) \
	WritePrivateProfileString(#location,#var,Safe_IntToAscii(##location.##var),fn);
//#define WRITE_INI_LONG(location,var) \
//	WritePrivateProfileString(#location,#var,Safe_LongToAscii(##location.##var),fn);
#define WRITE_INI_RULE_STRING(location,var) \
	WritePrivateProfileString(#location,#var ".Action",Safe_IntToAscii(##location.##var.Action),fn); \
	WritePrivateProfileString(#location,#var ".Value",##location.##var.Value,fn);
#define WRITE_INI_RULE_CHARACTERS(location,var) \
	WRITE_INI_RULE_STRING(location,var)
#define WRITE_INI_STRING(location,var) \
	WritePrivateProfileString(#location,#var,##location.##var,fn);
#define WRITE_INI_CSTRINGLIST(location,var) \
	WritePrivateProfileSection(#location "." #var,INI.ToString(##location.##var),fn);
#define WRITE_INI_LIST(location,var) \
	WritePrivateProfileString(#location,#var,##location.##var.Enabled?"1":"0",fn);\
	WritePrivateProfileSection(#location "." #var,INI.ToString(##location.##var.List),fn);
#define WRITE_INI_RULE_LIST(location,var) \
	WritePrivateProfileString(#location,#var,Safe_IntToAscii(##location.##var.Action),fn);\
	WritePrivateProfileSection(#location "." #var,INI.ToString(##location.##var.List),fn);
#define WRITE_INI_MAP(location,var) \
	WritePrivateProfileString(#location,#var,##location.##var.Enabled?"1":"0",fn);\
	WritePrivateProfileSection(#location "." #var,INI.ToString(##location.##var.Map),fn);
#define WRITE_INI_RULE_MAP(location,var) \
	WritePrivateProfileString(#location,#var,Safe_IntToAscii(##location.##var.Action),fn);\
	WritePrivateProfileSection(#location "." #var,INI.ToString(##location.##var.Map),fn);

#define WRITE_INI_RULE_CACHE(location,var) \
	WritePrivateProfileString(#location,#var ".Action",Safe_IntToAscii(##location.##var.Action),fn);\
	WritePrivateProfileString(#location,#var ".MaxTime",Safe_IntToAscii(##location.##var.MaxTime),fn);\
	WritePrivateProfileString(#location,#var ".MaxCount",Safe_IntToAscii(##location.##var.MaxCount),fn);
#define WRITE_INI_CACHE(location,var) \
	WritePrivateProfileString(#location,#var ".Enabled",##location.##var.Enabled?"1":"0",fn);\
	WritePrivateProfileString(#location,#var ".MaxTime",Safe_IntToAscii(##location.##var.MaxTime),fn);\
	WritePrivateProfileString(#location,#var ".MaxCount",Safe_IntToAscii(##location.##var.MaxCount),fn);

//for backwards compatibility with WebKnight 3.2 and earlier
#define PARSE_XML_RULE_DENY(location,var,xmlkey) \
	PARSE_XML_RULE_PREFIX(location,var,xmlkey,"Deny_")
#define PARSE_XML_RULE_PREFIX(location,var,xmlkey,prefix) \
	if(name.CompareNoCase(prefix xmlkey)==0){ ##location.##var = Safe_AsciiToInt(CXML::Decode(val),##location.##var,##location.##var); }\
	else if(name.CompareNoCase(xmlkey)==0){ ##location.##var = Safe_AsciiToInt(CXML::Decode(val),##location.##var,##location.##var); }
#define PARSE_XML_RULE(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ ##location.##var = Safe_AsciiToInt(CXML::Decode(val),##location.##var,##location.##var); }
#define PARSE_XML_BOOL(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ if(val=="1"){ ##location.##var=true; }else{ if(val=="0"){ ##location.##var=false; }} }

//for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_RULE_INT_BACKWARDS(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ if(val.GetLength()==1){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }else{ ##location.##var.Value = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Value,##location.##var.Value); ##location.##var.Action = ##location.##var.Value>0; }}\
	else if(name.CompareNoCase("_" xmlkey)==0){ ##location.##var.Value = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Value,##location.##var.Value); }
//Limit_ and Max_ prefix for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_RULE_INT_LIMIT(location,var,xmlkey) \
	if(name.CompareNoCase("Limit_" xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase("Max_" xmlkey)==0){ ##location.##var.Value = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Value,##location.##var.Value); }\
	else if(name.CompareNoCase("Maximum_" xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase("_Maximum_" xmlkey)==0){ ##location.##var.Value = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Value,##location.##var.Value); }
#define PARSE_XML_RULE_INT(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase("_" xmlkey)==0){ ##location.##var.Value = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Value,##location.##var.Value); }
#define PARSE_XML_INT(location,var,xmlkey,cast) \
	if(name.CompareNoCase(xmlkey)==0){ ##location.##var = ##cast Safe_AsciiToInt(CXML::Decode(val),##location.##var,##location.##var); }
//#define PARSE_XML_LONG(location,var,xmlkey,cast) \
//	if(name.CompareNoCase(xmlkey)==0){ ##location.##var = ##cast Safe_AsciiToLong(CXML::Decode(val),##location.##var,##location.##var); }
#define PARSE_XML_RULE_STRING(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase("_" xmlkey)==0){ ##location.##var.Value = CXML::Decode(val); }
//for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_RULE_STRING_LIMIT(location,var,xmlkey) \
	if(name.CompareNoCase("Limit_" xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase("Max_" xmlkey)==0){ ##location.##var.Value = CXML::Decode(val); }\
	else if(name.CompareNoCase("Maximum_" xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase("_Maximum_" xmlkey)==0){ ##location.##var.Value = CXML::Decode(val); }
//for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_RULE_CHARACTERS_DENY(location,var,xmlkey) \
	if(name.CompareNoCase("Deny_" xmlkey)==0){ ##location.##var.Value = CXML::Decode(val); ##location.##var.Action = ##location.##var.Value.GetLength()>0?1:0; }\
	else if(name.CompareNoCase(xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase("_" xmlkey)==0){ ##location.##var.Value = CXML::Decode(val); }
//for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_RULE_CHARACTERS_BACKWARDS(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ if(IsNumeric(val)){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }else{ ##location.##var.Value = CXML::Decode(val); ##location.##var.Action = ##location.##var.Value.GetLength()>0?1:0; }}\
	else if(name.CompareNoCase("_" xmlkey)==0){ ##location.##var.Value = CXML::Decode(val); }
#define PARSE_XML_RULE_CHARACTERS(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase("_" xmlkey)==0){ ##location.##var.Value = CXML::Decode(val); }
#define PARSE_XML_STRING(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ ##location.##var = CXML::Decode(val); }
#define PARSE_XML_CSTRINGLIST(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ XML.ToObject(val,##location.##var); }
#define PARSE_XML_CMAPSTRINGTOSTRING(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ XML.ToObject(val,##location.##var); }
//Use_ + val.GetLength() for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_RULE_LIST_USE(location,var,xmlkey) \
	if(name.CompareNoCase("Use_" xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase(xmlkey)==0){ if(val.GetLength()==1) { ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }else{ XML.ToObject(val,##location.##var.List);} }\
	else if(name.CompareNoCase("_" xmlkey)==0){ XML.ToObject(val,##location.##var.List); }
#define PARSE_XML_RULE_LIST(location,var,xmlkey) \
	if(name.CompareNoCase(xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase("_" xmlkey)==0){ XML.ToObject(val,##location.##var.List); }
//Use_ & GetLength() for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_LIST(location,var,xmlkey) \
	if(name.CompareNoCase("Use_" xmlkey)==0){ ##location.##var.Enabled = val=="1"?true:false; } \
	else if(name.CompareNoCase(xmlkey)==0){ if(val.GetLength()==1){ ##location.##var.Enabled = val=="1"?true:false; }else{ XML.ToObject(val,##location.##var.List); } }\
	else if(name.CompareNoCase("_" xmlkey)==0){ XML.ToObject(val,##location.##var.List); }
//for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_RULE_MAP_PREFIX(location,var,xmlkey,prefix) \
	if(name.CompareNoCase("Use_" prefix xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase(prefix xmlkey)==0){ XML.ToObject(val,##location.##var.Map); }\
	else if(name.CompareNoCase(xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase("_" xmlkey)==0){ XML.ToObject(val,##location.##var.Map); }
//Use_ + val.GetLength() for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_RULE_MAP(location,var,xmlkey) \
	if(name.CompareNoCase("Use_" xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }\
	else if(name.CompareNoCase(xmlkey)==0){ if(val.GetLength()==1) { ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); }else{ XML.ToObject(val,##location.##var.Map); } }\
	else if(name.CompareNoCase("_" xmlkey)==0){ XML.ToObject(val,##location.##var.Map); }
//Use_ + val.GetLength() for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_MAP(location,var,xmlkey) \
	if(name.CompareNoCase("Use_" xmlkey)==0){ ##location.##var.Enabled = val=="1"?true:false; } \
	else if(name.CompareNoCase(xmlkey)==0){ if(val.GetLength()==1) { ##location.##var.Enabled = val=="1"?true:false; }else{ XML.ToObject(val,##location.##var.Map); } }\
	else if(name.CompareNoCase("_" xmlkey)==0){ XML.ToObject(val,##location.##var.Map); }

//Use_ for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_RULE_CACHE(location,var,xmlkey) \
	if(name.CompareNoCase("Use_" xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); } \
	else if(name.CompareNoCase(xmlkey)==0){ ##location.##var.Action = Safe_AsciiToInt(CXML::Decode(val),##location.##var.Action,##location.##var.Action); } \
	else if(name.CompareNoCase(xmlkey "_Max_Count")==0){ ##location.##var.MaxCount = Safe_AsciiToInt(CXML::Decode(val)); } \
	else if(name.CompareNoCase(xmlkey "_Max_Time")==0){ ##location.##var.MaxTime = Safe_AsciiToInt(CXML::Decode(val)); }
//Use_ for backwards compatibility with WebKnight 3.2 and previous
#define PARSE_XML_CACHE(location,var,xmlkey) \
	if(name.CompareNoCase("Use_" xmlkey)==0){ ##location.##var.Enabled = val=="1"?true:false; } \
	else if(name.CompareNoCase(xmlkey)==0){ ##location.##var.Enabled = val=="1"?true:false; } \
	else if(name.CompareNoCase(xmlkey "_Max_Count")==0){ ##location.##var.MaxCount = Safe_AsciiToInt(CXML::Decode(val)); } \
	else if(name.CompareNoCase(xmlkey "_Max_Time")==0){ ##location.##var.MaxTime = Safe_AsciiToInt(CXML::Decode(val)); }

#define WRITE_XML_RULE(location,var,xmlkey,explanation) \
	xml += XML.ToXML(xmlkey,"Select",Safe_IntToAscii(##location.##var),Safe_IntToAscii(d.##location.##var),explanation,RULE_SELECTION);
#define WRITE_XML_BOOL(location,var,xmlkey,explanation) \
	xml += XML.ToXML(xmlkey,"Option",##location.##var?"1":"0",d.##location.##var?"1":"0",explanation);
#define WRITE_XML_RULE_INT(location,var,xmlkey,explanation) \
	xml += XML.ToXML(xmlkey,"Select",Safe_IntToAscii(##location.##var.Action),Safe_IntToAscii(d.##location.##var.Action),"",RULE_SELECTION);\
	xml += XML.ToXML("_" xmlkey,"Text",Safe_IntToAscii(##location.##var.Value),Safe_IntToAscii(d.##location.##var.Value),explanation);
#define WRITE_XML_INT(location,var,xmlkey,explanation) \
	xml += XML.ToXML(xmlkey,"Text",Safe_IntToAscii(##location.##var),Safe_IntToAscii(d.##location.##var),explanation);
//#define WRITE_XML_LONG(location,var,xmlkey,explanation) \
//	xml += XML.ToXML(xmlkey,"Text",Safe_LongToAscii(##location.##var),Safe_LongToAscii(d.##location.##var),explanation);
#define WRITE_XML_RULE_STRING(location,var,xmlkey,explanation) \
	xml += XML.ToXML(xmlkey,"Select",Safe_IntToAscii(##location.##var.Action),Safe_IntToAscii(d.##location.##var.Action),"",RULE_SELECTION); \
	xml += XML.ToXML("_" xmlkey,"Text",##location.##var.Value,d.##location.##var.Value,explanation);
#define WRITE_XML_RULE_CHARACTERS(location,var,xmlkey,explanation) \
	WRITE_XML_RULE_STRING(location,var,xmlkey,explanation)
#define WRITE_XML_STRING(location,var,xmlkey,explanation) \
	xml += XML.ToXML(xmlkey,"Text",##location.##var,d.##location.##var,explanation);

#define WRITE_XML_RULE_LIST(location,var,xmlkey,explanation1, explanation2) \
	xml += XML.ToXML(xmlkey,"Select",Safe_IntToAscii(##location.##var.Action),Safe_IntToAscii(d.##location.##var.Action),explanation1,RULE_SELECTION); \
	xml += XML.ToXML("_" xmlkey,##location.##var.List,explanation2);
#define WRITE_XML_LIST(location,var,xmlkey,explanation1, explanation2) \
	xml += XML.ToXML(xmlkey,"Option",##location.##var.Enabled?"1":"0",d.##location.##var.Enabled?"1":"0",explanation1); \
	xml += XML.ToXML("_" xmlkey,##location.##var.List,explanation2);

#define WRITE_XML_RULE_MAP(location,var,xmlkey,explanation1, explanation2) \
	xml += XML.ToXML(xmlkey,"Select",Safe_IntToAscii(##location.##var.Action),Safe_IntToAscii(d.##location.##var.Action),explanation1,RULE_SELECTION); \
	xml += XML.ToXML("_" xmlkey,##location.##var.Map,explanation2);
#define WRITE_XML_MAP(location,var,xmlkey,explanation1, explanation2) \
	xml += XML.ToXML(xmlkey,"Option",##location.##var.Enabled?"1":"0",d.##location.##var.Enabled?"1":"0",explanation1); \
	xml += XML.ToXML("_" xmlkey,##location.##var.Map,explanation2);

#define WRITE_XML_CSTRINGLIST(location,var,xmlkey,explanation) \
	xml += XML.ToXML(xmlkey,##location.##var,explanation);
#define WRITE_XML_RULE_CACHE(location,var,xmlkey,explGeneral,explCount,explTime) \
	xml += XML.ToXML(xmlkey,"Select",Safe_IntToAscii(##location.##var.Action),Safe_IntToAscii(d.##location.##var.Action),explGeneral,RULE_SELECTION); \
	xml += XML.ToXML(xmlkey "_Max_Count","Text",Safe_IntToAscii(##location.##var.MaxCount),Safe_IntToAscii(d.##location.##var.MaxCount),explCount); \
	xml += XML.ToXML(xmlkey "_Max_Time","Text",Safe_IntToAscii(##location.##var.MaxTime),Safe_IntToAscii(d.##location.##var.MaxTime),explTime);
#define WRITE_XML_CACHE(location,var,xmlkey,explGeneral,explCount,explTime) \
	xml += XML.ToXML(xmlkey,"Option",##location.##var.Enabled?"1":"0",d.##location.##var.Enabled?"1":"0",explGeneral); \
	xml += XML.ToXML(xmlkey "_Max_Count","Text",Safe_IntToAscii(##location.##var.MaxCount),Safe_IntToAscii(d.##location.##var.MaxCount),explCount); \
	xml += XML.ToXML(xmlkey "_Max_Time","Text",Safe_IntToAscii(##location.##var.MaxTime),Safe_IntToAscii(d.##location.##var.MaxTime),explTime);

	//general classes
	interface ISetting{
	public:
		bool Enabled;
	};

	class _StringList: public ISetting{
	public:
		CStringList List;
	};

	class _StringMap: public ISetting{
	public:
		CMapStringToString Map;
	};

	class _StringCache: public ISetting{
	public:
		unsigned int MaxTime;
		unsigned int MaxCount;
	};

	//rules (with select)
	interface IRule{
	public:
		Rule Action;
	};

	template <class T>
	class RuleTemplate: public IRule{
	public:
		T Value;
	};

	typedef RuleTemplate<int> RuleInt;
	typedef RuleTemplate<CString> RuleCharacters;
	typedef RuleTemplate<CString> RuleString;

	class RuleStringList: public IRule{
	public:
		CStringList List;
	};

	class RuleStringMap: public IRule{
	public:
		CMapStringToString Map;
	};

	class RuleStringCache: public IRule{
	public:
		unsigned int MaxTime;
		unsigned int MaxCount;
	};

class CSettings: public CStringHelper, public CObject
{
public:
	CString GetLoadedSettingsFileName();
	virtual bool ApplyConstraints();
	virtual bool ProcessFile(LPCTSTR fn);
	virtual CString ToXML() = 0;
	virtual bool WriteToFile(LPCTSTR fn);
	virtual bool WriteToRegistry();
	virtual bool WriteToActiveDirectory();

	virtual bool UpdateFromFile(bool force = false);

	virtual bool ReadFromActiveDirectory();
	virtual bool ReadFromRegistry();
	virtual bool ParseXML(CString& key, CString& val) = 0;
	virtual bool ReadFromFile(LPCTSTR fn);
	virtual void LoadDefaults() { Version = 0.0; IsUpgradeInProgress = false; };
	
	virtual bool Update(bool force = false);
	virtual void Upgrade(){};
	bool IsUpgradeInProgress;
	virtual void Patch();
	virtual void Patch(CString FileName);
	CMapStringToString Patches;
	float Version;
	CFileStamp FileStamp;

	CCriticalSection crit;

	CSettings();
	virtual ~CSettings();

protected:
	virtual bool WriteToFileINI(LPCTSTR fn) = 0;
	virtual bool WriteToFileXML(LPCTSTR fn) = 0;
	virtual bool ReadFromFileINI(LPCTSTR fn) = 0;
	virtual bool ReadFromFileXML(LPCTSTR fn);

	class _XML {
	public:
		static void ToObject(CString& val, CMapStringToString& map);
		static void ToObject(CString& val, CStringList& list);

		static CString ToXML(LPCTSTR tag, LPCTSTR app, LPCTSTR value, LPCTSTR defaultvalue, LPCTSTR explanation = _T(""), LPCTSTR attributes = _T(""));
		static CString ToXML(LPCTSTR tag, CMapStringToString& map, LPCTSTR explanation = _T(""));
		static CString ToXML(LPCTSTR tag, CStringList& List, LPCTSTR explanation = _T(""));

		static bool WriteEntityToFile(LPCTSTR fn, LPCTSTR XML);
		static bool WriteEntityToFile(LPCTSTR fn, LPCTSTR EntityName, LPCTSTR XML);
		static CString AddSeparator(LPCTSTR key);
	} XML;

	class _INI {
	public:
		static CString ToString(const CMapStringToString& map);
		static CString ToString(const CStringList& list);

		static void CleanupUCase(CStringList& list);
		static void CleanupLCase(CStringList& list);
		static void Cleanup(CStringList& list);

		static void CleanupUCase(CString &str);
		static void CleanupLCase(CString& str);
		static void Cleanup(CString& str);
	} INI;

};

#endif // !defined(AFX_SETTINGS_H__270445F3_48E4_49D3_8EAF_CAB52E330BF9__INCLUDED_)
