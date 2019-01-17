/*
    AQTRONIX C++ Library
    Copyright 2004-2016 Parcifal Aertssen

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
// HTTPFirewallSettings.h: interface for the CHTTPFirewallSettings class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_HTTPFIREWALLSETTINGS_H__58F563F1_7F52_4F31_9119_AA03546009B0__INCLUDED_)
#define AFX_HTTPFIREWALLSETTINGS_H__58F563F1_7F52_4F31_9119_AA03546009B0__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "FirewallSettings.h"
#include "WebAgents.h"
#include "Signatures.h"
#include "ParameterSettings.h"
#include "BlockListCollection.h"
#include "HeaderValidation.h"
#include "ExperimentalSettings.h"

class CHTTPFirewallSettings : public CFirewallSettings  
{
public:
	CString ToXML();
	bool ReadFromFile(LPCTSTR fn);

	bool Update(bool force = false);
	void ReadAgentsFile(LPCTSTR Path);
	virtual void LoadAgents(){};

	virtual bool ApplyConstraints();

	bool ProcessFile(LPCTSTR fn);
	void LoadDefaults();
	CHTTPFirewallSettings();
	virtual ~CHTTPFirewallSettings();

	//SCANNING ENGINE
	class _Engine{
	public:
		bool ScanNonSecurePort;
		bool ScanSecurePort;
		bool AllowLateScanning;
		bool IsPHP;	//true when Allow_PHP is set
		_StringList ExcludedInstances;
	} Engine;

	//RESPONSE HANDLING
	class _HTTPResponse{
	public:
		bool DropConnection;
		bool UseStatus;
		CString Status;
		DWORD StatusCode;
		CString StatusMessage;
		CString RedirectURL;
		bool Redirect;
		CString Contents;
		bool Directly;
		bool MonitorIP;
		unsigned int MonitorIPTimeout;
		_StringCache BlockIP; //don't use RuleStringCache!
		void SyncStatusCode()
		{
			int pos = Status.Find(' ');
			if(pos>-1){
				StatusCode = CStringHelper::Safe_AsciiToInt(Status.Left(pos),999,999);
				StatusMessage = Status.Mid(pos);
			}else{
				StatusCode = CStringHelper::Safe_AsciiToInt(Status,999,999);
				StatusMessage = Status;
			}
		}
	} HTTPResponse;
	
	//LOGGING
	class _HTTPLogging{
	public:
		bool LogHostHeader;
		bool LogUserAgent;
		bool Log_HTTP_X_FORWARDED_FOR;
		bool Log_HTTP_VIA;
	} HTTPLogging;

	//CONNECTION
	class _Connection{
	public:
		RuleStringCache RequestsLimit;
		CString ClientIPVariable;
		bool ChangeLogIPVariable;
		_StringList MonitorAddresses;
		_StringList DenyAddresses;
		_StringList ExcludedAddresses;

		class _BlockLists : 
			public CBlockListCollection, 
			public IRule {
		} BlockLists;

	} Connection;

	//AUTHENTICATION
	class _Authentication{
	public:
		bool NotifyAuthentication;
		bool ScanAccountAllEvents;
		bool ScanExcludedInstances;
		Rule BlankPasswords;
		Rule SamePasswordAsUsername;
		RuleStringList DenyDefaultPasswords;
		RuleStringCache BruteForceAttack;
		Rule SystemAccounts;
		RuleStringList AllowAccounts;
		RuleStringList DenyAccounts;
		//forms authentication
		bool ScanForms;
		CStringList UsernameFields;
		CStringList PasswordFields;
		Rule FormParameterPollution;
	} Authentication;

	//HTTP Version
	class _HTTPVersion{
	public:
		RuleInt MaxLength;
		RuleStringList Allow;
	} HTTPVersion;

	//URL SCANNING
	class _URL{
	public:
		Rule RFCCompliantURL;
		Rule RFCCompliantHTTPURL;
		Rule BadParser;
		bool UseRawScan;
		Rule MultipleCGI;
		Rule Escaping;
		Rule AlternateStream;
		Rule Backslash;
		Rule TrailingDotInDir;
		Rule ParentPath;
		Rule EncodingExploits;
		Rule HighBitShellcode;
		Rule SpecialWhitespace;
		RuleInt MaxLength;
		RuleCharacters Characters;
		RuleStringList DenySequences;
		RuleStringMap DenyRegex;
		RuleStringList Allow;
		RuleStringCache RequestsLimit;
		_StringList ExcludedURL;
	} URL;

	//QUERYSTRING
	class _QueryString{
	public:
		bool UseRawScan;
		Rule EncodingExploits;
		Rule HighBitShellcode;
		Rule SpecialWhitespace;
		Rule DirectoryTraversal;
		RuleInt MaxLength;
		RuleParameters Parameters;
		RuleInt MaxVariableLength;
		Rule SQLInjection;
		RuleStringList DenySequences;
		RuleStringMap DenyRegex;
		_StringList ExcludedQueryString;
	} QueryString;

	//MAPPED PATH
	class _Path{
	public:
		Rule SpecialWhitespace;
		Rule Escaping;
		Rule ParentPath;
		Rule MultipleColons;
		RuleCharacters Characters;
		Rule Dot;
		RuleStringList AllowPaths;
	} Path;

	//REQUESTED FILE
	class _Filename{
	public:
		bool UseRawScan;
		Rule DefaultDocument;
		RuleCharacters Characters;
		RuleStringList Deny;
		_StringList Monitor;
	} Filename;

	//EXTENSION
	class _Extensions{
	public:
		RuleStringList Allow;
		RuleStringList Deny;
		RuleStringCache RequestsLimit;
		CStringList LimitExtensions;
	} Extensions;

	//HEADERS
	class _Headers{
	public:
		RuleStringList DenyHeaders;
		Rule HighBitShellcode;
		Rule EncodingExploits;
		Rule DirectoryTraversal;
		RuleInt MaxLength;
		RuleStringMap MaxHeaders;
		Rule SQLInjection;
		RuleStringList DenySequences;
		RuleStringMap DenyRegex;
		CHeaderValidation Validation;
	} Headers;

	//HEADERS - Host
	class _Host{
	public:
		Rule RFCCompliant;
		RuleStringList AllowHosts;
		RuleStringList DenyHosts;
		_StringList AllowDenyHostsAccess;
		_StringList Excluded;
	} Host;

	//HEADERS - ContentType
	class _ContentType{
	public:
		RuleStringList Allow;
		RuleStringList Deny;
		RuleStringMap MaxLength;
		RuleString MaxContentLength; //CString object!!!
	} ContentType;

	//HEADERS - TransferEncoding
	class _TransferEncoding {
	public:
		RuleStringList Allow;
		RuleStringList Deny;
	} TransferEncoding;

	//HEADERS - COOKIE
	class _Cookie{
	public:
		bool HttpOnly;
		bool Secure;
		Rule HighBitShellcode;
		Rule SpecialWhitespace;
		Rule DirectoryTraversal;
		Rule EncodingExploits;
		RuleParameters Parameters;
		RuleInt MaxVariableLength;
		Rule SQLInjection;
		RuleStringList DenySequences;
	} Cookie;

	//HEADERS - USER AGENT
	class _UserAgent{
	public:
		RuleStringList DenyUserAgents;
		RuleStringList DenySequences;
		Rule NonRFC;
		Rule SQLInjection;
		Rule HighBitShellcode;
		Rule SpecialWhitespace;
		Rule Empty;
		RuleCharacters RequireCharacter;
		RuleStringCache Switching;
		RuleStringList CurrentDate;
		_StringList Excluded;
	} UserAgent;

	//METHODS
	class _Verbs{
	public:
		RuleStringList DenyPayload;
		RuleStringList DenyVerbs;
		RuleStringList AllowVerbs;
	} Verbs;

	//GLOBAL FILTER CAPABILITIES
	class _Global{
	public:
		bool IsInstalledAsGlobalFilter;
		bool IsInstalledInWebProxy;
		Rule SlowHeaderAttack;
		Rule SlowPostAttack;
	} Global;

	//POST
	class _Post{
	public:
		Rule RFCCompliant;
		Rule SQLInjection;
		Rule HighBitShellcode;
		Rule EncodingExploits;
		Rule DirectoryTraversal;
		RuleParameters Parameters;
		RuleInt MaxVariableLength;
		RuleStringList DenySequences;
		RuleStringMap DenyRegex;
		int LogLength;
	} Post;

	//RESPONSE MONITORING
	class _ResponseMonitor{
	public:
		CString ServerHeader;
		bool ChangeServerHeader;
		bool RemoveServerHeader;

		_StringMap Headers; //don't use RuleStringMap!
		bool LogClientErrors;
		bool LogServerErrors;
		RuleStringCache ClientErrors;
		RuleStringCache ServerErrors;
		RuleStringMap InformationDisclosure;
		bool IsNeeded() { return /* Headers.Enabled || done in OnSendResponse */ LogClientErrors || LogServerErrors || ClientErrors.Action || ServerErrors.Action || InformationDisclosure.Action; }
		void SyncServerHeader(bool updatemap = false)
		{
			if(updatemap){
				if(RemoveServerHeader){
					Headers.Map.SetAt(_T("Server:"),_T(""));
				}else if(ChangeServerHeader){
					Headers.Map.SetAt(_T("Server:"),ServerHeader);
				}
			}else{
				CString val;
				if(Headers.Map.Lookup(_T("Server:"),val)){
					if(val==_T("")){
						RemoveServerHeader = true;
					}else{
						RemoveServerHeader = false;
						ChangeServerHeader = true;
						ServerHeader = val;
					}
				}else{
					RemoveServerHeader = ChangeServerHeader = false;
				}
			}
		}
	} ResponseMonitor;
	
	//SQL INJECTION
	class _SQLi{
	public:
		CStringList Keywords;
		int AllowedCount;
		bool NormalizeWhitespace;
		bool ReplaceNumericWithOne;
	} SQLi;

	//ENCODING EXPLOITS
	class _EncodingExploits{
	public:
		CStringList Keywords;
		CMapStringToString Regex;
		bool ScanDoubleEncoding;
		bool ScanInvalidUTF8;
	} EncodingExploits;

	//AGENTS DATABASE
	class _Agents{
	public:
		CWebAgents AgentList;
		bool BlockDataMiningCommercial;
		bool BlockDataMiningPublic;
		bool BlockDownloadManagers;
		bool BlockEmailHarvesting;
		bool BlockGuestbookSpammers;
		bool BlockHackTools;
		bool BlockImageDownloaders;
		bool BlockIndexing;
		bool BlockMonitoring;
		bool BlockOfflineBrowsers;
		bool BlockOtherBad;
		bool BlockTrademark;
		bool BlockValidationTools;
		bool BlockLinkChecking;
		bool BlockBrowsers;
		bool BlockMediaPlayers;
		bool BlockProxies;
		bool BlockAdware;
		bool BlockBrowserExtensions;
		bool BlockSpyware;
		bool BlockEditing;
		//bool BlockDevice;
		bool BlockNewsFeed;
		bool BlockSearchEngines;
		bool BlockFilteringSoftware;
		bool BlockSoftwareComponent;
		bool BlockTranslation;
		bool BlockSEO;
		bool BlockMailClients;
	}Agents;

	class _Referrer{
	public:
		bool UseScan;
		Rule RFCCompliantURL;
		Rule RFCCompliantHTTPURL;
		Rule BadParser;
		Rule SQLInjection;
		Rule EncodingExploits;
		Rule HighBitShellcode;
		Rule SpecialWhitespace;
		RuleCharacters Characters;
		RuleStringList Allow;
		RuleStringList Deny;
		RuleStringList DenySequences;
		_StringList Excluded;

		bool HotLinking;
		CStringList HotLinkingFileExtensions;
		CStringList HotLinkingUrls;
		RuleStringList HotLinkingAllowDomains;
		RuleStringList HotLinkingDenyDomains;
		bool HotLinkingUseHostHeader;
		Rule HotLinkingBlankReferrer;
	}Referrer;

	class _Admin{
	public:
		bool Enabled;
		CString Url;
		CStringList FromIP;
		CString Login;
		bool AllowConfigChanges;
		CFileName dll;
		CString ServerHeader;
		float Version;
		CTime Started;
	}Admin;

	CParameterSettings ApplicationParameters;
	
	class _UA {
	public:
		CTime LastUpdated;
		CStringList CurrentDates;
	} UA;

	CExperimentalSettings Experimental;

protected:
	CString GetXMLEncodingExploits(CHTTPFirewallSettings& d);
	CString GetXMLSQLInjection(CHTTPFirewallSettings& d);
	CString GetXMLCookie(CHTTPFirewallSettings& d);
	CString GetXMLUserAgent(CHTTPFirewallSettings& d);
	CString GetXMLReferrer(CHTTPFirewallSettings& d);
	CString GetXMLHotLinking(CHTTPFirewallSettings& d);
	CString GetXMLLogging(CHTTPFirewallSettings& d);
	CString GetXMLHTTPVerbs(CHTTPFirewallSettings &d);
	CString GetXMLResponseMonitor(CHTTPFirewallSettings& d);
	CString GetXMLGlobalFilterCapabilities(CHTTPFirewallSettings& d);
	CString GetXMLQuerystring(CHTTPFirewallSettings& d);
	CString GetXMLPost(CHTTPFirewallSettings& d);
	CString GetXMLContentType(CHTTPFirewallSettings& d);
	CString GetXMLHost(CHTTPFirewallSettings& d);
	CString GetXMLHTTPHeaders(CHTTPFirewallSettings& d);
	CString GetXMLRequestedExtension(CHTTPFirewallSettings& d);
	CString GetXMLRequestedFile(CHTTPFirewallSettings& d);
	CString GetXMLMappedPath(CHTTPFirewallSettings& d);
	CString GetXMLURLScanning(CHTTPFirewallSettings& d);
	CString GetXMLRequestLimits(CHTTPFirewallSettings& d);
	CString GetXMLAuthentication(CHTTPFirewallSettings& d);
	CString GetXMLConnectionControl(CHTTPFirewallSettings& d);
	CString GetXMLResponseHandling(CHTTPFirewallSettings& d);
	CString GetXMLScanningEngine(CHTTPFirewallSettings& d);
	CString GetXMLAdmin(CHTTPFirewallSettings& d);
	bool WriteToFileXML(LPCTSTR fn);
	bool WriteToFileINI(LPCTSTR fn);
	bool ParseXML(CString& key, CString& val);
	bool ReadFromFileINI(LPCTSTR fn);
	bool ReadFromFileURLScan(LPCTSTR fn);
};

#endif // !defined(AFX_HTTPFIREWALLSETTINGS_H__58F563F1_7F52_4F31_9119_AA03546009B0__INCLUDED_)
