/*
    AQTRONIX C++ Library
    Copyright 2003-2006 Parcifal Aertssen

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
// HTML.cpp: implementation of the CHTML class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "HTML.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

/* Changelog
 * 2006.04.02: Added HTMLToTags()
 *
 */

CHTML::CHTML()
{

}

CHTML::~CHTML()
{

}

CString CHTML::HTMLToText(CString &html)
{
	int length(html.GetLength());
	bool skip(false);
	CString text("");
	if(length<0)
		length=0;
	for(int i=0;i<length;i++){
		//start skipping htmltag
		if(html[i]=='<'){
			skip = true;
			if(i+2<length && (  (html[i+1]=='b' || html[i+1]=='B') &&
								(html[i+2]=='r' || html[i+2]=='R') &&
								(html[i+3]=='>')					  ) ){
				text += "\r\n";
			}
		}else{
			//copy everything else
			if(!skip){
				text += html[i];
			}
			//stop skipping htmltag
			if(html[i]=='>'){
				skip = false;
			}
		}
	}
	Decode(text);
	return text;
}

CString CHTML::HTMLToTags(CString &html)
{
	int length(html.GetLength());
	bool skip(true);
	CString text("");
	if(length<0)
		length=0;
	for(int i=0;i<length;i++){
		//start skipping htmltag
		if(html[i]=='<'){
			skip = false;
		}
		//copy everything else
		if(!skip){
			text += html[i];
		}
		//stop skipping htmltag
		if(html[i]=='>'){
			skip = true;
		}
	}
	return text;
}

CString& CHTML::Encode(CString& text)
{
	//standard encoded characters
	text.Replace(_T("&"),_T("&amp;"));
	text.Replace(_T("<"),_T("&lt;"));
	text.Replace(_T(">"),_T("&gt;"));
	text.Replace(_T("'"),_T("&apos;"));
	text.Replace(_T("\""),_T("&quot;"));
	
	return text;
}

CString CHTML::Decode(LPCTSTR html)
{
	CString str(html);
	return Decode(str);
}

CString& CHTML::Decode(CString& html)
{
	//standard encoded characters (ascii<127)
	html.Replace(_T("&lt;"),_T("<"));
	html.Replace(_T("&gt;"),_T(">"));
	html.Replace(_T("&apos;"),_T("'"));
	html.Replace(_T("&quot;"),_T("\""));
	html.Replace(_T("&frasl;"),_T("/"));

	//ascii<127 not standard encoded
	html.Replace(_T("&Tab;"),_T("\t"));		//tabulator
	html.Replace(_T("&NewLine;"),_T("\n"));	//new line
	html.Replace(_T("&excl;"),_T("!"));
	html.Replace(_T("&num;"),_T("#"));
	html.Replace(_T("&dollar;"),_T("$"));
	html.Replace(_T("&percnt;"),_T("%"));
	html.Replace(_T("&plus;"),_T("+"));
	html.Replace(_T("&colon;"),_T(":"));
	html.Replace(_T("&equals;"),_T("="));
	html.Replace(_T("&sol;"),_T("/"));
	html.Replace(_T("&bsol;"),_T("\\"));

	//standard encoded characters (ascii>127)
	html.Replace(_T("&ndash;"),_T("-"));	//en dash
	html.Replace(_T("&mdash;"),_T("-"));	//em dash
	html.Replace(_T("&nbsp;"),_T(" "));		//nonbreaking space
	html.Replace(_T("&iexcl;"),_T("¡"));	//inverted exclamation
	html.Replace(_T("&cent;"),_T("¢"));		//cent sign
	html.Replace(_T("&pound;"),_T("£"));	//pound sterling
	html.Replace(_T("&curren;"),_T("¤"));	//general currency sign
	html.Replace(_T("&yen;"),_T("¥"));		//yen sign
	html.Replace(_T("&brvbar;"),_T("¦"));	//broken vertical bar
	html.Replace(_T("&brkbar;"),_T("¦"));	//broken vertical bar
	html.Replace(_T("&sect;"),_T("§"));		//section sign
	html.Replace(_T("&uml;"),_T("¨"));		//umlaut
	html.Replace(_T("&die;"),_T("¨"));		//umlaut
	html.Replace(_T("&copy;"),_T("©"));		//copyright
	html.Replace(_T("&ordf;"),_T("ª"));		//feminine ordinal
	html.Replace(_T("&laquo;"),_T("«"));	//left angle quote
	html.Replace(_T("&not;"),_T("¬"));		//not sign
	html.Replace(_T("&shy;"),_T("­"));		//soft hyphen
	html.Replace(_T("&reg;"),_T("®"));		//registered trademark
	html.Replace(_T("&macr;"),_T("¯"));		//macron accent
	html.Replace(_T("&hibar;"),_T("¯"));	//macron accent
	html.Replace(_T("&deg;"),_T("°"));		//degree sign
	html.Replace(_T("&plusmn;"),_T("±"));	//plus or minus
	html.Replace(_T("&sup2;"),_T("²"));		//superscript two
	html.Replace(_T("&sup3;"),_T("³"));		//superscript three
	html.Replace(_T("&acute;"),_T("´"));	//acute accent
	html.Replace(_T("&micro;"),_T("µ"));	//micro sign
	html.Replace(_T("&para;"),_T("¶"));		//paragraph sign
	html.Replace(_T("&middot;"),_T("·"));	//middle dot
	html.Replace(_T("&cedil;"),_T("¸"));	//cedilla
	html.Replace(_T("&sup1;"),_T("¹"));		//superscript one
	html.Replace(_T("&ordm;"),_T("º"));		//masculine ordinal
	html.Replace(_T("&raquo;"),_T("»"));	//right angle quote
	html.Replace(_T("&frac14;"),_T("¼"));	//one-fourth
	html.Replace(_T("&frac12;"),_T("½"));	//one-half
	html.Replace(_T("&frac34;"),_T("¾"));	//three-fourths
	html.Replace(_T("&iquest;"),_T("¿"));	//inverted question mark
	html.Replace(_T("&Agrave;"),_T("À"));	//uppercase A, grave accent
	html.Replace(_T("&Aacute;"),_T("Á"));	//uppercase A, acute accent
	html.Replace(_T("&Acirc;"),_T("Â"));	//uppercase A, circumflex accent
	html.Replace(_T("&Atilde;"),_T("Ã"));	//uppercase A, tilde
	html.Replace(_T("&Auml;"),_T("Ä"));		//uppercase A, umlaut
	html.Replace(_T("&Aring;"),_T("Å"));	//uppercase A, ring
	html.Replace(_T("&AElig;"),_T("Æ"));	//uppercase AE
	html.Replace(_T("&Ccedil;"),_T("Ç"));	//uppercase C, cedilla
	html.Replace(_T("&Egrave;"),_T("È"));	//uppercase E, grave accent
	html.Replace(_T("&Eacute;"),_T("É"));	//uppercase E, acute accent
	html.Replace(_T("&Ecirc;"),_T("Ê"));	//uppercase E, circumflex accent
	html.Replace(_T("&Euml;"),_T("Ë"));		//uppercase E, umlaut
	html.Replace(_T("&Igrave;"),_T("Ì"));	//uppercase I, grave accent
	html.Replace(_T("&Iacute;"),_T("Í"));	//uppercase I, acute accent
	html.Replace(_T("&Icirc;"),_T("Î"));	//uppercase I, circumflex accent
	html.Replace(_T("&Iuml;"),_T("Ï"));		//uppercase I, umlaut
	html.Replace(_T("&ETH;"),_T("Ð"));		//uppercase Eth, Icelandic
	html.Replace(_T("&Ntilde;"),_T("Ñ"));	//uppercase N, tilde
	html.Replace(_T("&Ograve;"),_T("Ò"));	//uppercase O, grave accent
	html.Replace(_T("&Oacute;"),_T("Ó"));	//uppercase O, acute accent
	html.Replace(_T("&Ocirc;"),_T("Ô"));	//uppercase O, circumflex accent
	html.Replace(_T("&Otilde;"),_T("Õ"));	//uppercase O, tilde
	html.Replace(_T("&Ouml;"),_T("Ö"));		//uppercase O, umlaut
	html.Replace(_T("&times;"),_T("×"));	//multiplication sign
	html.Replace(_T("&Oslash;"),_T("Ø"));	//uppercase O, slash
	html.Replace(_T("&Ugrave;"),_T("Ù"));	//uppercase U, grave accent
	html.Replace(_T("&Uacute;"),_T("Ú"));	//uppercase U, acute accent
	html.Replace(_T("&Ucirc;"),_T("Û"));	//uppercase U, circumflex accent
	html.Replace(_T("&Uuml;"),_T("Ü"));		//uppercase U, umlaut
	html.Replace(_T("&Yacute;"),_T("Ý"));	//uppercase Y, acute accent
	html.Replace(_T("&THORN;"),_T("Þ"));	//uppercase THORN, Icelandic
	html.Replace(_T("&szlig;"),_T("ß"));	//lowercase sharps, German
	html.Replace(_T("&agrave;"),_T("à"));	//lowercase a, grave accent
	html.Replace(_T("&aacute;"),_T("á"));	//lowercase a, acute accent
	html.Replace(_T("&acirc;"),_T("â"));	//lowercase a, circumflex accent
	html.Replace(_T("&atilde;"),_T("ã"));	//lowercase a, tilde
	html.Replace(_T("&auml;"),_T("ä"));		//lowercase a, umlaut
	html.Replace(_T("&aring;"),_T("å"));	//lowercase a, ring
	html.Replace(_T("&aelig;"),_T("æ"));	//lowercase ae
	html.Replace(_T("&ccedil;"),_T("ç"));	//lowercase c, cedilla
	html.Replace(_T("&egrave;"),_T("è"));	//lowercase e, grave accent
	html.Replace(_T("&eacute;"),_T("é"));	//lowercase e, acute accent
	html.Replace(_T("&ecirc;"),_T("ê"));	//lowercase e, circumflex accent
	html.Replace(_T("&euml;"),_T("ë"));		//lowercase e, umlaut
	html.Replace(_T("&igrave;"),_T("ì"));	//lowercase i, grave accent
	html.Replace(_T("&iacute;"),_T("í"));	//lowercase i, acute accent
	html.Replace(_T("&icirc;"),_T("î"));	//lowercase i, circumflex accent
	html.Replace(_T("&iuml;"),_T("ï"));		//lowercase i, umlaut
	html.Replace(_T("&eth;"),_T("ð"));		//lowercase eth, Icelandic
	html.Replace(_T("&ntilde;"),_T("ñ"));	//lowercase n, tilde
	html.Replace(_T("&ograve;"),_T("ò"));	//lowercase o, grave accent
	html.Replace(_T("&oacute;"),_T("ó"));	//lowercase o, acute accent
	html.Replace(_T("&ocirc;"),_T("ô"));	//lowercase o, circumflex accent
	html.Replace(_T("&otilde;"),_T("õ"));	//lowercase o, tilde
	html.Replace(_T("&ouml;"),_T("ö"));		//lowercase o, umlaut
	html.Replace(_T("&divide;"),_T("÷"));	//division sign
	html.Replace(_T("&oslash;"),_T("ø"));	//lowercase o, slash
	html.Replace(_T("&ugrave;"),_T("ù"));	//lowercase u, grave accent
	html.Replace(_T("&uacute;"),_T("ú"));	//lowercase u, acute accent
	html.Replace(_T("&ucirc;"),_T("û"));	//lowercase u, circumflex accent
	html.Replace(_T("&uuml;"),_T("ü"));		//lowercase u, umlaut
	html.Replace(_T("&yacute;"),_T("ý"));	//lowercase y, acute accent
	html.Replace(_T("&thorn;"),_T("þ"));	//lowercase thorn, Icelandic
	html.Replace(_T("&yuml;"),_T("ÿ"));		//lowercase y, umlaut

	//Decode characters that cannot be represented
	//in pure ascii text
	html.Replace(_T("&lsquo;"),_T("‘"));	//left single quote
	html.Replace(_T("&rsquo;"),_T("’"));	//right single quote
	html.Replace(_T("&sbquo;"),_T("?"));	//single low-9 quote
	html.Replace(_T("&ldquo;"),_T("?"));	//left double quote
	html.Replace(_T("&rdquo;"),_T("?"));	//right double quote
	html.Replace(_T("&bdquo;"),_T("?"));	//double low-9 quote
	html.Replace(_T("&dagger;"),_T("?"));	//dagger
	html.Replace(_T("&Dagger;"),_T("?"));	//double dagger
	html.Replace(_T("&permil;"),_T("?"));	//per mill sign
	html.Replace(_T("&lsaquo;"),_T("?"));	//single left-pointing angle quote
	html.Replace(_T("&rsaquo;"),_T("?"));	//single right-pointing angle quote
	html.Replace(_T("&spades;"),_T("?"));	//black spade suit
	html.Replace(_T("&clubs;"),_T("?"));	//black club suit
	html.Replace(_T("&hearts;"),_T("?"));	//black heart suit
	html.Replace(_T("&diams;"),_T("?"));	//black diamond suit
	html.Replace(_T("&oline;"),_T("?"));	//overline, = spacing overscore
	html.Replace(_T("&larr;"),_T("?"));		//leftward arrow
	html.Replace(_T("&uarr;"),_T("?"));		//upward arrow
	html.Replace(_T("&rarr;"),_T("?"));		//rightward arrow
	html.Replace(_T("&darr;"),_T("?"));		//downward arrow
	html.Replace(_T("&trade;"),_T("(TM)"));	//trademark sign

	//remove padding
	while(html.Find(_T("&#0"))>-1)
		html.Replace(_T("&#0"),_T("&#"));

	//normalize hex
	html.Replace(_T("&#X"),_T("&#x"));
	while(html.Find(_T("&#x0"))>-1)
		html.Replace(_T("&#x0"),_T("&#x"));	

	html.Replace(_T("&#xA"),_T("&#xa"));
	html.Replace(_T("&#xB"),_T("&#xb"));
	html.Replace(_T("&#xC"),_T("&#xc"));
	html.Replace(_T("&#xD"),_T("&#xd"));
	html.Replace(_T("&#xE"),_T("&#xe"));
	html.Replace(_T("&#xF"),_T("&#xf"));

	CString hex;
	for(char h = 'a'; h<'g'; h++){
		hex = "&#x";
		hex += h;
		html.Replace(hex + 'A',hex + 'a');
		html.Replace(hex + 'B',hex + 'b');
		html.Replace(hex + 'C',hex + 'c');
		html.Replace(hex + 'D',hex + 'd');
		html.Replace(hex + 'E',hex + 'e');
		html.Replace(hex + 'F',hex + 'f');
	}

	//Decode &#000; (decimal) and &#x00;(hex) values
	CString dec;
	char bufint[34] = "\0";
	char bufchar[2] = "\0";
	bufchar[1] = '\0';
	for(unsigned char c=255;c>0;c--){
		dec = "&#";
		hex = "&#x";
		dec += _itoa((int)c,bufint,10);
		hex += _itoa((int)c,bufint,16);
		bufchar[0] = c;
		html.Replace(dec + ';',bufchar);
		html.Replace(hex + ';',bufchar);

		//also without ending ; (see XSS evasion cheat sheet)
		html.Replace(dec,bufchar);
		html.Replace(hex,bufchar);

		//hex with capital A-F
		html.Replace(hex + ';',bufchar);
		html.Replace(hex,bufchar);
	}

	//last
	html.Replace(_T("&amp;"),_T("&"));

	return html;
}

CString CHTML::FilterTag(CString &HTML, CString TagName)
{
	/*
	 * Removes a tag from the html code
	 */

	//remove a tag: the "<TagName - </TagName>" part
	int taglength = TagName.GetLength()+3;
	int posstart(0); int posstop(-taglength);
	CString html(HTML);
	CString ret;
	html.MakeLower();

	posstart = html.Find("<" + TagName);

	while(posstart!=-1 && posstop!=-1 && posstop<posstart){
		ret += HTML.Mid(posstop+taglength,posstart-posstop-taglength);
		posstop = html.Find("</" + TagName + ">",__max(posstop+taglength,posstart));
		posstart = html.Find("<" + TagName,__max(posstart,posstop+taglength));
	}

	//rest of html
	if(posstop!=-1){
		ret += HTML.Mid(posstop+taglength);
	}
	
	return ret;
}



CString CHTML::ExtractTag(CString &HTML, CString TagName, int Start)
{
	/* 
	 * Extracts a tag at a certain position from first tag in the HTML
	 */
	//extract the "<tagname - </tagname>" part
	CString Tag(HTML);
	Tag.MakeLower();
	//find first tag in html, this is position zero!
	int posstart; posstart = Tag.Find("<" + TagName);
	if(posstart==-1)
		return "";
	//if start is not 0, add Start to posstart
	if(Start!=0){
		posstart+=Start;
		posstart = Tag.Find("<" + TagName,posstart);
		if(posstart==-1)
			return "";
	}
	//stop
	int posstop; posstop = Tag.Find("</" + TagName + ">",posstart);
	if(posstop==-1)
		posstop=HTML.GetLength()-1;
	//if ok, extract...
	if(posstart<posstop){
		Tag = HTML.Mid(posstart,posstop-posstart+TagName.GetLength()+3);
	}else{
		Tag = "";
	}
	return Tag;
}

CString CHTML::ExtractAllTags(CString &HTML, CString TagName)
{
	/*
	 * Extracts all tags from hmtl
	 */
	int pos(0);
	CString extract("");
	CString ret("");
	do{
		extract = ExtractTag(HTML,TagName,pos);
		ret += extract;
		pos += extract.GetLength();
	}while(extract!="");
	
	return ret;
}


