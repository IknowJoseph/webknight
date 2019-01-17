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
// Settings.cpp: implementation of the CSettings class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Settings.h"
#include "SandboxFile.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

/* CHANGELOG
 *
 *  2015.12.22 Switched to CSandboxFile instead of CFile
 *  2015.10.27 Fixed bug in parsing "App=" type, when explanation started with "Optionally" option type was detected
 *  2013.10.31 Added GetLoadedSettingsTimestamp() for WebKnight admin
 *  2013.03.25 Added GetLoadedSettingsFileName() which generates the Loaded.owner?.ext file format
 *  2013.03.23 Moved critical section object to this class (for CWebKnightExtension)
 *  2013.02.08 XML XMLAttributeValue() now using same ending separator as starting one
 *  2013.02.05 Added XSLT reference to GUI.xsl
 *  2006.09.25 Reading empty xml string/list/map is now actually empty instead of keeping the existing list
 *			   Added input validation for parsing xml bool & int values
 *  2006.04.29 Added GetReadSettingsFileName()
 *  2006.04.17 changed update parameters to TimeStamp class
 *  2005.10.02 Added WriteXMLEntityToFile() functions
 *             Made these functions pure virtual:
 *             ToXML(),LoadDefaults(),ParseXML(),WriteToFileXML(),WriteToFileINI()
 *             ReadFromFileINI()
 *  2005.07.18 Moved stringlist functions to new CStringHelper class
 *             Added ProcessFile() and ApplyConstraints()
 *  2004.09.29 Added overloaded function AddTo(CStringList&, CStringList)
 *  2004.02.09 ReadFromFileXML() can read large files, heap allocation instead of stack
 *             Did some optimization
 *  2004.02.03 Added virtual function ToXML() and ParseXML() uses CString& instead of CString
 *  2003.09.17 Fixed bug in ReadFromFileXML where it would stop parsing if value
 *             is an empty string in a list or map entity.
 *  2003.08.31 Fixed bug when changing timezone while running: call _tzset() before GetCurrentTime()
 *  2003.06.08 Class created
 */

CSettings::CSettings()
{
	LoadDefaults();
}

CSettings::~CSettings()
{

}

void CSettings::_INI::Cleanup(CString& str)
{
	//cleanup the string
	int pos = str.Find(';');	//drop everything after ';' (including the ';')
	if(pos>1){					//only if ';' is found and not on first and second position
		str = str.Left(pos);
		Trim(str);				//remove leading & trailing spaces & tabs & newlines
	}
}

void CSettings::_INI::CleanupLCase(CString &str)
{
	CSettings::_INI::Cleanup(str);	//clean it up
	CStringHelper::Safe_MakeLower(str);	//make it lowercase
}

void CSettings::_INI::CleanupUCase(CString &str)
{
	CSettings::_INI::Cleanup(str);	//clean it up
	CStringHelper::Safe_MakeUpper(str);	//make it uppercase
}

CString CSettings::_INI::ToString(const CStringList &list)
{
	CString str(_T(""));
	POSITION pos = list.GetHeadPosition();
	while(pos!=NULL){
		str = str + list.GetNext(pos) + _T("\r\n");
	}
	return str + '\0'; //double terminate it
}

CString CSettings::_INI::ToString(const CMapStringToString &map)
{
	CString str(""); CString k; CString v;
	POSITION pos = map.GetStartPosition();
	while(pos!=NULL){
		map.GetNextAssoc(pos,k,v);
		str = str + k + '=' + v + _T("\r\n");
	}
	return str + '\0'; //double terminate it
}

void CSettings::_INI::Cleanup(CStringList &list)
{
	POSITION pos;
	pos = list.GetHeadPosition();
	while (pos != NULL){
		CSettings::_INI::Cleanup(list.GetNext(pos));
	}
}

void CSettings::_INI::CleanupLCase(CStringList &list)
{
	POSITION pos;
	pos = list.GetHeadPosition();
	while (pos != NULL){
		CSettings::_INI::CleanupLCase(list.GetNext(pos));
	}
}

void CSettings::_INI::CleanupUCase(CStringList &list)
{
	POSITION pos;
	pos = list.GetHeadPosition();
	while (pos != NULL){
		CSettings::_INI::CleanupUCase(list.GetNext(pos));
	}
}

void CSettings::_XML::ToObject(CString& val, CStringList& list)
{
	CStringList l;
	CString tmp;
	for(int i=0;i<val.GetLength();i++){
		switch(val[i]){
		case '<':
			if(i+1<val.GetLength()){
				if(val[i+1]=='/'){
					if(i!=0){
						l.AddTail(CXML::Decode(tmp));
					}
				}
			}
			tmp = _T("");
			break;

		case '>':	//start of a value
			tmp = _T("");
			break;

		default:
			tmp += val[i];
			break;
		}
	}

	POSITION pos;
	pos = l.GetHeadPosition();
	list.RemoveAll();
	while(pos!=NULL){
		list.AddTail(l.GetNext(pos));
	}
}

void CSettings::_XML::ToObject(CString& val, CMapStringToString& map)
{
	CMapStringToString m; bool bkey(false); CString key; CString tmp;
	for(int i=0;i<val.GetLength();i++){
		switch(val[i]){
		case '<':
			if(i+1<val.GetLength()){
				if(val[i+1]=='/'){
					if(i!=0){
						if (!bkey){
							bkey = true;
							key = tmp;
						}else{
							bkey = false;
							m.SetAt(CXML::Decode(key),CXML::Decode(tmp));
						}
					}
				}
			}
			tmp = _T("");
			break;

		case '>':	//start of a value
			tmp = _T("");
			break;

		default:
			tmp += val[i];
			break;
		}
	}
	POSITION pos;
	CString k;
	CString v;
	pos = m.GetStartPosition();
	map.RemoveAll();
	while(pos!=NULL){
		m.GetNextAssoc(pos,k,v);
		map.SetAt(k,v);
	}
}

CString CSettings::_XML::ToXML(LPCTSTR tag, LPCTSTR app, LPCTSTR value, LPCTSTR defaultvalue, LPCTSTR explanation, LPCTSTR attributes)
{
	CString ret(_T("<"));
	ret += CXML::Encode(tag);
	ret += _T(" App='");
	ret += CXML::Encode(app);
	ret += _T("' Default='");
	ret += CXML::Encode(defaultvalue);
	ret += _T("' Explanation='");
	ret += CXML::Encode(explanation);
	ret += _T("'");
	if(_tcslen(attributes)>0){
		ret += _T(" ");
		ret += attributes;
	}
	ret += _T(">");
	ret += CXML::Encode(value);
	ret += _T("</");
	ret += CXML::Encode(tag);
	ret += _T(">\r\n");
	return ret;
}

CString CSettings::_XML::ToXML(LPCTSTR tag, CStringList &List, LPCTSTR explanation)
{
	CString ret(_T("<"));
	ret += CXML::Encode(tag);
	ret += _T(" App='List' Explanation='");
	ret += CXML::Encode(explanation);
	ret += _T("'>\r\n");
	
	POSITION pos;
	pos = List.GetHeadPosition();
	while(pos!=NULL){
		ret += _T("\t<Item>");
		ret += CXML::Encode(List.GetNext(pos));
		ret += _T("</Item>\r\n");
	}

	ret += _T("</");
	ret += CXML::Encode(tag);
	ret += _T(">\r\n");
	return ret;
}

CString CSettings::_XML::ToXML(LPCTSTR tag, CMapStringToString &map, LPCTSTR explanation)
{
	CString ret(_T("<"));
	ret += CXML::Encode(tag);
	ret += _T(" App='Map' Explanation='");
	ret += CXML::Encode(explanation);
	ret += _T("'>\r\n");

	POSITION pos; CString key; CString val;
	pos = map.GetStartPosition();
	while(pos!=NULL){
		map.GetNextAssoc(pos,key,val);
		ret += _T("\t<Key>");
		ret += CXML::Encode(key);
		ret += _T("</Key>");
		ret += _T("<Val>");
		ret += CXML::Encode(val);
		ret += _T("</Val>\r\n");
	}

	ret += _T("</");
	ret += CXML::Encode(tag);
	ret += _T(">\r\n");
	return ret;
}

bool CSettings::Update(bool force)
{
	//update settings (run-time update)
	return UpdateFromFile(force);
}

bool CSettings::UpdateFromFile(bool force)
{
	if (FileStamp.FileName.GetLength()>0) {
		if(force || FileStamp.HasChanged()){
			CString fn(FileStamp.FileName); //copy to keep pointer valid
			ReadFromFile(fn);				//reload settings
			return true;
		}
	}
	return false;
}

bool CSettings::ReadFromFile(LPCTSTR fn)
{
	try{

		//if file does not exist, return false
		if (!CFileName::FileExists(fn))//doesn't exist
			return false;

		//if file cannot be opened, return false
		CSandboxFile f;
		if(!f.Open(CFileName::GetDrivePrefix() + fn,CFile::modeRead|CFile::shareDenyWrite))
			return false;
		
		//set info for run-time update
		FileStamp.Set(fn,f);

		//close the file
		f.Close();

		if(ProcessFile(fn)){
			//Check constraints
			ApplyConstraints();
			return true;
		}else{
			return false;
		}
	}catch(...){
		return false;
	}
}

bool CSettings::ProcessFile(LPCTSTR fn)
{
	CFileName cfn(fn);
	if(cfn.ExtensionLCase == _T(".ini")){		//.ini file
		return ReadFromFileINI(fn);
	}else if(cfn.ExtensionLCase == _T(".xml")){		//.xml file
		return ReadFromFileXML(fn);
	}else{
		return false;							//unknown file type
	}
}

bool CSettings::ReadFromFileXML(LPCTSTR fn)
{
	/*
	 * read settings from an XML file
	 */
	char* buf = NULL;
	Version = 0.0;
	try{
		CSandboxFile file;
		if(file.Open(CFileName::GetDrivePrefix() + fn,CFile::modeRead|CFile::shareDenyWrite)){
			//get size
			const ULONGLONG sz = file.GetLength();
			if(sz>0 && sz<SETTINGS_MAX_XML_FILE){
				buf = new char[sz+1];
				if(buf!=NULL){
					//read file
					int bread = file.Read(buf,sz);
					buf[bread] = '\0';	//null terminate
					file.Close();
				
					//xml string
					CString xml(buf);
					delete[] buf;

					//parse string
					int length = xml.GetLength();
					CString key; bool bkey(false);
					CString val; bool bval(false);
					bool blarge(false);
					CString tmp;
					CString type;
					int pos;
					CString list;
					bool nostop(false);
					for(int i=0;i<length;i++){
						switch(xml[i]){	
						case '<':	//start of a key/end of value
							if(nostop){
								int lenkey = key.Find(' ');
								if(lenkey!=-1){
									CString keyname(key.Left(lenkey));
									if(i+2+lenkey<length && keyname == xml.Mid(i+2,lenkey)){
										nostop = false;
										blarge = true;
									}else{
										//if closing tag is already read, because of empty val
										if(tmp.Left(lenkey+2) == _T("</") + keyname){
											nostop = false;
											blarge = true;
											tmp = _T("");
										}else{
											tmp += xml[i];
										}
									}
								}
							}
							if(!nostop){
								val = tmp;
								tmp = _T("");
								bkey = true;
							}
							if(!nostop && bkey && bval){
								if(key.Left(1)!='?'){	//ignore this (<?xml version...)
									if(key.Left(1)!='/'){	//is it end of entity?
										pos = key.Find(_T("App="));
										if(pos!=-1){
											int posend = key.Find(' ',pos);
											if(posend!=-1){
												type = key.Mid(pos+4,posend-pos-4);
											}else{
												type = key.Mid(pos+4);
											}
										}else{
											type=_T("");
											//Parse version
											if(Version==0.0f){
												pos = key.Find(_T("Version="));
												if(pos!=-1){
													Version = Safe_AsciiToFloat(CXML::AttributeValue(key,_T("Version")));
												}
											}
										}
										CStringHelper::Safe_MakeLower(type);
										if(type.Find(_T("list"))!=-1){
											if(blarge){
												ParseXML(key,val);
												blarge = bval = bkey = false;
											}else{
												tmp += xml[i];
												nostop = true;
											}
										}else if(type.Find(_T("map"))!=-1){
											if(blarge){
												ParseXML(key,val);
												blarge = bval = bkey = false;
											}else{
												tmp += xml[i];
												nostop = true;
											}
										}else{
											ParseXML(key,val);
											bval = bkey = false;
										}
									}
								}
							}
							break;

						case '>':	//start of a value
							if(nostop){ //don't stop, it's a list or map
								tmp += xml[i];
							}else{
								key = tmp;
								tmp = _T("");
								bval = true;
							}
							break;

						default:
							tmp += xml[i];
							break;
						}
					}
					return true;
				}
			}
		}
		return false;
	}catch(...){
		if(buf)
			delete[] buf;
		LoadDefaults();
		return false;
	}
}

bool CSettings::ApplyConstraints()
{
	return false;
}

bool CSettings::ReadFromRegistry()
{
	return false;
}

bool CSettings::ReadFromActiveDirectory()
{
	return false;
}

bool CSettings::WriteToRegistry()
{
	return false;
}

bool CSettings::WriteToActiveDirectory()
{
	return false;
}

bool CSettings::WriteToFile(LPCTSTR fn)
{
	/*
	 * Write settings to a given file (instance policy)
	 */
	try{

		//if file already exists, delete it
		if (CFileName::FileExists(fn)){
			if(!CFileName::DeleteFile(fn))		//delete file
				return false;		//return false if file could not be deleted
		}

		//if path does not exist, make it
		CFileName::CreatePath(CFileName(fn).Path);
		
		//look at extension to see what type of file it has to be
		CFileName cfn(fn);
		if (cfn.ExtensionLCase == _T(".xml")){		//XML file
			return WriteToFileXML(fn);
		}else if(cfn.ExtensionLCase == _T(".ini")){	//INI file
			return WriteToFileINI(fn);
		}else{
			//unknown file type
			CSandboxFile f;
			int openret;
			openret = f.Open(CFileName::GetDrivePrefix() + fn,CFile::modeCreate|CFile::modeWrite|CFile::shareDenyWrite);
			if (openret > 0) {
				const char buf[] = "AQTRONIX Settings\r\nError: unknown file type!\r\nAQTRONIX Settings encountered an unknown file type (extension) to write its settings to.\r\nTo implement this file type add the required functionality to the function WriteToFile() in the class CSettings.";
				f.Write(buf,strlen(buf));
				f.Close();
				return true;
			}else{
				return false;
			}
		}

	}catch(...){
		return false;
	}
}

bool CSettings::_XML::WriteEntityToFile(LPCTSTR fn,LPCTSTR EntityName,LPCTSTR XML)
{
	CString strXML(_T(""));
	strXML += _T("<") + CXML::Encode(EntityName) + _T(">\r\n");
	strXML += XML;
	strXML += _T("</") + CXML::Encode(EntityName) + _T(">\r\n");
	return WriteEntityToFile(fn, strXML);
}

bool CSettings::_XML::WriteEntityToFile(LPCTSTR fn, LPCTSTR XML)
{
	/* 
	 * Write all the settings to an XML file
	 * All checks on the file should have been
	 * done before this function is called
	 */
	try{
		
		CSandboxFile f;
		int openret;
		openret = f.Open(CFileName::GetDrivePrefix() + fn,CFile::modeCreate|CFile::modeWrite|CFile::shareDenyWrite);
		if (openret > 0) {
			CString strXML;
			strXML = CXML::Declaration();
			strXML += XML;

			f.Write(strXML,strXML.GetLength()*sizeof(TCHAR));
			f.Close();
			return true;
		}else{
			return false;
		}
	}catch(...){
		return false;
	}

}

CString CSettings::_XML::AddSeparator(LPCTSTR key)
{
	return _T("<") + CString(key) + _T(" App='Separator'/>\r\n");
	//TODO: 4.7 - Notes - support Note attribute
	return _T("<") + CString(key) + _T(" App='Separator' Note='edit note'/>\r\n");
}

CString CSettings::GetLoadedSettingsFileName()
{
	CFileName fn = FileStamp.FileName;
	int pos = fn.FileName.Find('.');
	if(pos>-1){
		fn.FileName = _T("Loaded") + fn.FileName.Mid(pos);
	}else{
		fn.FileName = _T("Loaded") + fn.Extension;
	}
	return fn.Path + fn.FileName;
}

void CSettings::Patch()
{
	Patch(FileStamp.FileName);
	Patches.RemoveAll();
}

void CSettings::Patch(CString FileName)
{	
	POSITION pos = Patches.GetStartPosition();
	if(pos!=NULL){
		CFileName fn(FileName);
		CString contents;
		if(fn.ReadFileToString(contents)){
			CString key;
			CString val;
			while(pos!=NULL){
				Patches.GetNextAssoc(pos,key,val);
				contents.Replace(key,val);
			}
			fn.WriteStringToFile(contents);
		}
	}
}
