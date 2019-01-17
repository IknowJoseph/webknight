/*
    AQTRONIX C++ Library
    Copyright 2015 Parcifal Aertssen

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
#include "WebAdmin.h"
#include "Filename.h"
#include "ProcessHelper.h"

CWebAdmin::CWebAdmin(void)
{
}

CWebAdmin::~CWebAdmin(void)
{
}

CString CWebAdmin::BuildMenu(CString HTMLMessage)
{
	//TODO: ADMIN - add Headers to menu
	CString body = "<p><a href=\"?\">Home</a> - <a href=\"?Log=Current\">Log</a> - <a href=\"?Settings=Dashboard\">Settings</a> - <a href=\"?Parameters=Dashboard\">Parameters</a> - <a href=\"?Robots=Dashboard\">Robots</a> - <a href=\"?Diagnostics=Dashboard\">Diagnostics</a> - <a href=\"?Help=Dashboard\">Help</a></p>\r\n";
	body += "<p><strong>" + HTMLMessage + "</strong></p>\r\n";
	return body;
}

CString CWebAdmin::BuildPage(CString title, CString& body)
{
	CString ret = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\r\n<html>\r\n<head>\r\n<title>" + title + "</title>\r\n<META name=\"ROBOTS\" content=\"NOINDEX, NOFOLLOW\">\r\n";
	
	//toggle display
	ret += " <script language=\"javascript\" type=\"text/javascript\">\r\n";
    ret += "    function ToggleDisplay(id) { ";
    ret += "        var divstyle = new String(); ";
    ret += "        divstyle = document.getElementById(id).style.display; ";
    ret += "        if (divstyle == \"block\" || divstyle == \"\") { ";
    ret += "            document.getElementById(id).style.display = \"none\"; ";
    ret += "        } ";
    ret += "        else { ";
    ret += "            document.getElementById(id).style.display = \"block\"; ";
    ret += "        } ";
    ret += "    } ";
	ret += " </script>\r\n";

	bool useCSS = false;
	if(useCSS){
		ret += "<link rel=\"stylesheet\" href=\"tacit.min.css\">";
		ret += "<link rel=\"stylesheet alternate\" title=\"W3\" href=\"w3.css\">";
		ret += "<link rel=\"stylesheet alternate\" title=\"Tacit\" href=\"tacit.min.css\">";
		ret += "<link rel=\"stylesheet alternate\" title=\"Sakura\" href=\"sakura.css\">";
		ret += "<link rel=\"stylesheet alternate\" title=\"Bare\" href=\"bare.min.css\">";
	}
	ret += AddJS();

	ret += "</head>\r\n";

	if(useCSS)
		ret += "<body>\r\n";
	else
		ret += "<body text=\"#000000\" vlink=\"#FF3300\" link=\"#FF3300\" bgcolor=\"#ffffff\"><font face=\"Verdana,Arial,Helvetica\" size=\"2\">\r\n";
	ret += "<h2>" + title + "</h2>\r\n";

	ret += body;

	//end
	if(!useCSS)
		ret += "</font>\r\n";

	ret += "</body>\r\n</html>";

	return ret;
}

CString CWebAdmin::AddJS()
{
	CString ret = "";

	//jquery
	//ret += "<script src=\"./js/jquery-1.9.1.js\"></script>\r\n";

	//tabletools (uses jquery)
	//ret += "<link rel=\"stylesheet\" href=\"./js/DataTables-1.10.12/jquery.dataTables.min.css\" />\r\n";
	//ret += "<script type=\"text/javascript\" src=\"./js/DataTables-1.10.12/jquery.dataTables.min.js\"></script>\r\n";
	//ret += "<script>$(document).ready(function(){"
	//		"$('.collapsibletable').DataTable();"
	//		"});</script>\r\n";

	//accordion
	//ret += "<link rel=\"stylesheet\" href=\"./js/jquery-ui.css\" />\r\n";
	//ret += "<script src=\"./js/jquery-ui.js\"></script>\r\n";
	//ret += "<script>$(document).ready(function(){"
	//	"$(\".accordion\" ).accordion({ active: false, collapsible: true  });"
	//	"});</script>\r\n";

	return ret;
}

CString CWebAdmin::AddTitle(CString htmltitle)
{
	return "<h3>" + htmltitle + "</h3>\r\n";
}

CString CWebAdmin::AddParagraph(CString htmltext)
{
	return "<p>" + htmltext + "</p>\r\n";
}

CString CWebAdmin::AddPreformatted(CString htmltext)
{
	return "<pre>" + htmltext + "</pre>\r\n";
}

CString CWebAdmin::WarnNoScript()
{
	return "<noscript><p><strong><font color=\"red\">This functionality requires JavaScript to be enabled!</font></strong></p></noscript>\r\n";
}

CString CWebAdmin::ToTable(LPCTSTR Title, CStringCache& cache, bool ShowValue)
{
	return CollapsibleTable(Title,cache.ToString("|||", ShowValue),cache.Count(),0/*cache.GetByteCount()*/);
}

CString CWebAdmin::ToTable(LPCTSTR Title, CIPRangeList& list)
{
	return CollapsibleTable(Title,list.ToString("|||"),list.Count(),0/*list.GetByteCount()*/);
}

CString CWebAdmin::ToTable(LPCTSTR Title, CMapStringToPtr& map, LPCTSTR Column1, LPCTSTR Column2)
{
	int count = map.GetCount();
	CString ret = "<p>";
	CString key = Title;
	key.Replace(' ','_');
	ret += Title;
	ret += " (" + CStringHelper::Safe_IntToAscii(count) + ")";
	if(count>0){
		ret += " <a href=\"javascript:ToggleDisplay(\'";
		ret += key;
		ret += "\');\">+</a>";
	}
	ret += "</p>\r\n";

	CString k;
	void* p;
	POSITION pos = map.GetStartPosition();
	if(pos!=NULL){
		ret += "<div id=\"";
		ret += key;
		ret += "\" style=\"display:none;\">\r\n";
		ret += "<table class=\"collapsibletable\" border=\"1\">\r\n";

		ret += "<thead><tr><th>\r\n";
		ret += Column1;
		ret += "</th><th>";
		ret += Column2;
		ret += "</th></tr></thead>\r\n<tbody>\r\n";

		while(pos!=NULL){
			map.GetNextAssoc(pos,k,(void*&)p);
			ret += "<tr><td>" + CHTML::Encode(k) + "</td><td>";
			(p==NULL) ? ret += "<font color=\"red\">ERROR</font>": ret+= "<font color=\"green\">OK</font>";
			ret += "</td></tr>\r\n";
		}
		ret += "</tbody>\r\n</table>\r\n</div>\r\n";
	}
	return ret;
}

CString CWebAdmin::CollapsibleTable(LPCTSTR Title, CString& Text, unsigned int count, unsigned int size)
{
	//title
	CString ret = "<p>";
	ret += Title;
	CString key = Title;
	key.Replace(' ','_');
	ret += " (" + CStringHelper::Safe_IntToAscii(count);
	if(size>0)
		ret += " items , " + CStringHelper::Safe_LongToAscii(size) + " bytes";
	ret += ")";
	if(count>0){
		ret += " <a href=\"javascript:ToggleDisplay(\'";
		ret += key;
		ret += "\');\">+</a>";
	}
	ret += "</p>\r\n";
	//items
	ret += "<div id=\"";
	ret += key;
	ret += "\" style=\"display:none;\">\r\n";
	ret += "<table border=\"1\" class=\"collapsibletable\" id=\"table_";
	ret += key;
	ret += "\">\r\n";

	ret += "<thead><tr><th>"; 
	ret += Title;
	ret += "</th></tr></thead>\r\n";

	ret += "<tbody>\r\n<tr><td>";
	CString contents = CHTML::Encode(Text);
	contents.Replace("|||","</td></tr>\r\n<tr><td>");
	ret += contents;
	ret += "</td></tr>\r\n</tbody>\r\n</table>\r\n</div>\r\n";

	return ret;
}

CString CWebAdmin::AddRow(CString Key, CString Value)
{
	return "<tr><td>" + Key + ":</td><td>" + Value + "</td></tr>\r\n";
}

CString CWebAdmin::AddRow(CString Column1, CString Column2, CString Column3)
{
	return "<tr><td>" + Column1 + "</td><td>" + Column2 + "</td><td>" + Column3 + "</td></tr>\r\n";
}

CString CWebAdmin::AddRow(CString Column1, CString Column2, CString Column3, CString Column4)
{
	return "<tr><td>" + Column1 + "</td><td>" + Column2 + "</td><td>"  + Column3 + "</td><td>" + Column4 + "</td></tr>\r\n";
}

CString CWebAdmin::GetQueryStringValue(CString& QueryString, CString Key)
{
	CString value = "";
	CString param = '&' + Key + '=';
	int pos = QueryString.Find(param);
	if(pos==-1){
		param = Key + '=';
		pos = QueryString.Find(param);
		if(pos!=0)  //first parameter in query string
			pos = -1;
	}
	if(pos>-1 && pos<QueryString.GetLength()-param.GetLength()){
		value = QueryString.Mid(pos+param.GetLength());
		pos = value.Find("&");
		if(pos>-1){
			value = value.Left(pos);
		}
		value = CURL::Decode(value);
	}
	return value;
}

CString CWebAdmin::BuildForm(CString Name, CString URL, CMapStringToString& map)
{
	CString form("");
	POSITION pos = map.GetStartPosition();
	CString key;
	CString val;
	form += "<form name=\"frm" + CHTML::Encode(Name) + "\" action=\"" + URL + "\" method=\"POST\">\r\n";
	form += "<textarea rows=\"5\" cols=\"80\" name=\"" + CHTML::Encode(Name) + "\">\r\n";
	while(pos!=NULL){
		map.GetNextAssoc(pos,key,val);
		form += CHTML::Encode(key) + "=" + CHTML::Encode(val) + "\r\n";
	}
	form += "</textarea>\r\n";
	form +=	"<input type=\"submit\" name=\"btn_sub\" value=\"Add\"></td></tr>\r\n";
	form += "</form>\r\n";
	return form;
}

CString CWebAdmin::BuildParameterForm(CString Dashboard, CString Section, CMapStringToString& map, CString URL)
{
	CString body("");
	body += "<strong>" + CHTML::Encode(Section) + "</strong> <a href=\"?" + CURL::Encode(Dashboard) + "=Clear&Clear=" + CURL::Encode(Section) + "\">Clear</a>\r\n";
	body += BuildForm(Section + "_Validators",URL,map);
	return body;
}

CString CWebAdmin::InstallFile(CString fn, CString src_path, CString dest_path)
{
	if(CFileName::Exists(dest_path + fn)){
		return "File " + dest_path + fn + " already exists";
	}else{
		if(CopyFile(src_path + fn,dest_path + fn,true)){
			return "Copied " + fn + " -> " + dest_path + fn;
		}else{
			DWORD err_code = GetLastError();
			//needs IIS_IUSRS change permission on your website
			return "Failed copying " + fn + " -> " + dest_path + fn + " (Error code " + CStringHelper::Safe_DWORDToAscii(err_code) + ": " + CProcessHelper::GetErrorDescription(err_code) + ")";
		}
	}
}
