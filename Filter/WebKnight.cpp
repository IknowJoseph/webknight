/*
	AQTRONIX WebKnight - ISAPI Filter for securing IIS
	Copyright 2002-2016 Parcifal Aertssen

	This file is part of AQTRONIX WebKnight.

    AQTRONIX WebKnight is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation; either version 2 of the
	License, or (at your option) any later version.

    AQTRONIX WebKnight is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with AQTRONIX WebKnight; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/
// WEBKNIGHT.CPP - Implementation file for your Internet Server
//    WebKnight Filter


#include "stdafx.h"
#include "Globals.h"
#include "WebKnight.h"

#define STRING2(x) #x
#define STRING(x) STRING2(x)

#ifdef _MSC_VER
#pragma message("***** _MSC_VER:" STRING(_MSC_VER) " *****")
#if _MSC_VER > 1200
						//VS 6.0 = MSC 1200
						//VS 2005 = MSC 1400
						//VS 2008 = MSC 1500
#else
#pragma message("***** To avoid errors, make sure you add the project Library folder to your include sources (Tools->Options->Directories). *****")
#endif
#endif

/* AQTRONIX WebKnight
 *
 * See README.TXT for information about the source code
 *
 * 13 August    2002: Project started
 * 26 October   2002: Started coding a GUI for settings
 *  4 November  2002: Beta 1.0 released (without GUI)
 * 12 January   2003: First version of GUI finished
 * 25 February  2003: Windows Installer package finished
 * 24 March     2003: Final 1.0 released (+config 1.0)						VS 6.0
 * 14 July      2003: Final 1.1 released (+config 1.1)						VS 6.0
 *  8 September 2003: Final 1.2 released (+config 1.1)						VS 6.0
 * 10 November  2003: Final 1.3 released (+config 1.2)						VS 6.0
 * 24 December  2006: Final 2.0 released (+config 1.3 + loganalysis 1.0)	VS 8.0 (2005)
 *  8 October   2007: Final 2.1 released (+config 1.3 + loganalysis 1.1)	VS 6.0
 *  2 September 2008: Final 2.2 released (+config 1.4 + loganalysis 1.2)	VS 8.0 (2005)
 *  3 April     2010: Final 2.3 released (+config 1.5 + loganalysis 1.3)	VS 9.0 (2008)
 * 29 December  2010: Final 2.4 released (+config 1.5 + loganalysis 1.4)	VS 9.0 (2008)
 * 18 November  2012: Final 2.5 released (+config 1.6 + loganalysis 1.4)	VS 9.0 (2008)
 *  4 April		2013: Final 3.0 released (+config 1.7 + loganalysis 1.5)	VS 9.0 (2008)
 * 31 July		2013: Final 3.1 released (+config 1.8 + loganalysis 1.5)	VS 9.0 (2008)
 *  7 April		2014: Final 3.2 released (+config 1.8 + loganalysis 1.5)	VS 9.0 (2008)
 * 11 November	2014: Final 4.0 released (+config 2.0 + loganalysis 1.6)	VS 9.0 (2008)
 * 05 February	2015: Final 4.1 released (+config 2.0 + loganalysis 1.7)	VS 9.0 (2008)
 * 01 July		2015: Final 4.2 released (+config 2.0 + loganalysis 1.7.1)	VS 9.0 (2008)
 * 07 October	2015: Final 4.3 released (+config 2.1 + loganalysis 1.8)	VS 9.0 (2008)
 * 11 November	2015: Final 4.4 released (+config 2.2 + loganalysis 1.8)	VS 9.0 (2008)
 * 05 April		2016: Final 4.5 released (+config 2.2 + loganalysis 1.8.2)	VS 9.0 (2008)
 * 08 November	2017: Final 4.6 released (+config 2.3 + loganalysis 1.8.4)	VS 9.0 (2008)
 *
 * You can not define _UNICODE because this program is not made for it and the
 * ISAPI framework does not support Unicode.
 * If you still want to enable this you have to review every piece of code and
 * adjust all char types, "str" functions,...
 *
 * For IIS6 (and up) you cannot register for the OnReadRawData event if IIS is
 * running in Worker Process mode (only works in IIS 5.0 Isolation mode).
 *
 */

//TODO: 4.7 - installer for all users (set ALLUSERS=to that of previous version, new install set ALLUSERS=1)
//			(in start menu of all users instead of user start menu etc...) test on IIS 5 and IIS 7+
//			test upgrade from 4.6.1 correctly detected for same user? + start menu paths changes?
//			test NTFS permissies met ALLUSERS=1 LogonUser change permission?
//https://stackoverflow.com/questions/12110987/windows-installer-uninstalling-previous-version-when-the-versions-differ-in-in

//TODO: 4.x - features 4.x on website

//TODO: 4.7 - scanning engine - create owner settings files (only supported on IIS 7+)
//TODO: 4.7 - xml config 3.1 with bugfix to save settings after closing wizard

/* TODO: WEBKNIGHT
 *	<5.0>
 * - IIS Module
 * - Incident Response -> set server variable (SetHeader() only possible in OnPreprocHeaders)
 *
 *	<5.1>
 * - fully multithreaded scanning engine (not just thread safe)
 * - log file per web instance / single file logging like urlscan 3.0 beta
 *
 * FEATURES UNDER CONSIDERATION
 * - captcha alternative / data analysis to detect bots and spamming POST messages
 * 		- http://www.stopforumspam.com/apis (90.152.30.61 zit er in en heeft gespamd)
 *		- http://isc.sans.org/diary.html?storyid=1836
 *		- session not initialized or no jpg/gif/css file requested
 *		- http://www.usenix.org/events/nsdi05/tech/kandula/kandula_html/
 *
 * WANTED FEATURES
 * - Central Policy Management: Settings in local file or Active Directory (+schedules, +organizational unit, +multiple policies)
 * - MMC or tabsheet plugin for IIS: using own GUI XML protocol for future compatibility
 *
 * REJECTED FEATURES
 * - installer: lock isapi extension (for all websites). Can be easily locked in IIS Manager + ISAPI Filter cannot be locked/unlocked in IIS Manager
 * - import modsecurity rules
 * - block countries: IP ranges can already be imported (like from ipdeny.com) + should be done at router level
 * - print loaded settings (only options) to the log file (when a load/reload of settings happens) REJECTED: too much settings, this is not urlscan!
 * - compare settings with previously loaded settings when printing settings to log file
 * - validHostport (see kodeit), this is stupid because of HTTP 0.9 and HTTP 1.0 requests still possible
 * - Logging: W3C extended log format: too limited!
 * - Logging backup: database logging or backup can be scheduled by OS
 * - Settings in Registry: why use that when you have XML or LDAP?
 *
 * POSSIBLE EXPLOITS IN IIS:
 * - Ms-Echo-Request header??
 * - VERBS (from winhttp.dll & SEARCH exploit?)
 * - headers (from winhttp.dll)
 * - encoding exploits UTF-8, Shift-JIS, EUC-JP...
 *
 * BUGS IN WEBKNIGHT
 * - Settings: INI file: writing ';' in SQL Keywords cannot be read by ReadFrom function -> WILL NOT BE FIXED (Reason: INI settings not used by default)
 *
 * BUGS IN IIS/ISAPI FRAMEWORK:
 * 1) When attack detected in OnReadRawData -> no OnSendRawData event (server header not
 *    changed or removed and filtercontext not reset). SOLUTION: added code in HackResponse().
 *    Only works with ResponseDirectly=1! If you redirect to a url or only send back a
 *    ResponseStatus then server header is not changed.
 * 2) On IIS 7.x and later when an ISAPI filter registers for the SF_NOTIFY_SEND_RAW_DATA an
 *    error "arithmetic operation resulted in an overflow" occurs in IIS if you want to
 *    download files larger than 256 MiB.
 *    2013.03.25 - reported bug to Microsoft
 * 3) IHttpRequest->GetRemainingEntityBytes() sometimes returns 0 even when there is data
 *    -> When pressing F5 in IE on form submission on Win8 (verified 2015.03)
 *    -> When using multipart/form-data
 *    -> When using chunked encoding but Content-Length header is set to 0
 */

///////////////////////////////////////////////////////////////////////
// The one and only CWebKnightFilter object

CWebKnightFilter theFilter;

//map DLL entry functions
extern "C" DWORD WINAPI HttpFilterProc(PHTTP_FILTER_CONTEXT pfc, DWORD dwNotificationType, LPVOID pvNotification){
	return theFilter.HttpFilterProc(pfc,dwNotificationType,pvNotification);
}
extern "C" BOOL WINAPI GetFilterVersion(PHTTP_FILTER_VERSION pVer){
	return theFilter.GetFilterVersion(pVer);
}

///////////////////////////////////////////////////////////////////////
// The one and only CWebKnightExtension object

// ISAPI Extension (IIS 6 isapi wildcard alternative to global filtering)
// mapping .* (including dot!!) -> "C:\Program Files\AQTRONIX WebKnight\WebKnight.dll"
CWebKnightExtension theExtension(theFilter.Settings, theFilter.logger); //same settings/log as filter

//map DLL entry functions
extern "C" BOOL WINAPI GetExtensionVersion(HSE_VERSION_INFO *pVer){
	return theExtension.GetExtensionVersion(pVer);
}
extern "C" DWORD WINAPI HttpExtensionProc(EXTENSION_CONTROL_BLOCK *pECB){
	return theExtension.HttpExtensionProc(pECB);
}
extern "C" BOOL WINAPI TerminateExtension(DWORD dwFlags){
	return theExtension.TerminateExtension(dwFlags);
}

// Do not edit the following lines, which are needed by ClassWizard.
#if 0
BEGIN_MESSAGE_MAP(CWebKnightFilter, CISAPIFilter)
	//{{AFX_MSG_MAP(CWebKnightFilter)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()
#endif	// 0

///////////////////////////////////////////////////////////////////////
// If your extension will not use MFC, you'll need this code to make
// sure the extension objects can find the resource handle for the
// module.  If you convert your extension to not be dependent on MFC,
// remove the comments around the following AfxGetResourceHandle()
// and DllMain() functions, as well as the g_hInstance global.

/****

static HINSTANCE g_hInstance;

HINSTANCE AFXISAPI AfxGetResourceHandle()
{
	return g_hInstance;
}

BOOL WINAPI DllMain(HINSTANCE hInst, ULONG ulReason,
					LPVOID lpReserved)
{
	if (ulReason == DLL_PROCESS_ATTACH)
	{
		g_hInstance = hInst;
	}

	return TRUE;
}

****/



