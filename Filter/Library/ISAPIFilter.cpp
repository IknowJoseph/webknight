/*
    AQTRONIX C++ Library
    Copyright 2005-2013 Parcifal Aertssen

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
// ISAPIFilter.cpp : implementation file
//

#include "stdafx.h"
#include "ISAPIFilter.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CISAPIFilter

CISAPIFilter::CISAPIFilter()
{
}

CISAPIFilter::~CISAPIFilter()
{
}


// Do not edit the following lines, which are needed by ClassWizard.
#if 0
BEGIN_MESSAGE_MAP(CISAPIFilter, CHttpFilter)
	//{{AFX_MSG_MAP(CISAPIFilter)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()
#endif	// 0

/////////////////////////////////////////////////////////////////////////////
// CISAPIFilter member functions

//MFC ISAPI replacement

DWORD CISAPIFilter::HttpFilterProc(PHTTP_FILTER_CONTEXT pfc, DWORD dwNotificationType, LPVOID pvNotification)
{
	switch(dwNotificationType){
		case SF_NOTIFY_READ_RAW_DATA:
			return OnReadRawData(pfc,(PHTTP_FILTER_RAW_DATA)pvNotification);
		case SF_NOTIFY_PREPROC_HEADERS:
			return OnPreprocHeaders(pfc,(PHTTP_FILTER_PREPROC_HEADERS)pvNotification);
		case SF_NOTIFY_AUTHENTICATION:
			return OnAuthentication(pfc,(PHTTP_FILTER_AUTHENT)pvNotification);
		case SF_NOTIFY_URL_MAP:
			return OnUrlMap(pfc,(PHTTP_FILTER_URL_MAP)pvNotification);
		case SF_NOTIFY_ACCESS_DENIED:
			return OnAccessDenied(pfc,(PHTTP_FILTER_ACCESS_DENIED)pvNotification);
		case SF_NOTIFY_SEND_RESPONSE:
			return OnSendResponse(pfc,(PHTTP_FILTER_SEND_RESPONSE)pvNotification);
		case SF_NOTIFY_SEND_RAW_DATA:
			return OnSendRawData(pfc,(PHTTP_FILTER_RAW_DATA)pvNotification);
		case SF_NOTIFY_LOG:
			return OnLog(pfc,(PHTTP_FILTER_LOG)pvNotification);
		case SF_NOTIFY_END_OF_REQUEST:
			return OnEndOfRequest(pfc);
		case SF_NOTIFY_END_OF_NET_SESSION:
			return OnEndOfNetSession(pfc);
		case SF_NOTIFY_AUTH_COMPLETE:
			return OnAuthComplete(pfc,(PHTTP_FILTER_AUTH_COMPLETE_INFO)pvNotification);
		default:
			return SF_STATUS_REQ_NEXT_NOTIFICATION;
	}
}

BOOL CISAPIFilter::GetFilterVersion(PHTTP_FILTER_VERSION pVer)
{
	pVer->dwFlags = SF_NOTIFY_ORDER_DEFAULT;
	if(pVer->dwServerFilterVersion < HTTP_FILTER_REVISION){
		//Never report a higher version than server version for backwards compatibility:
		//ISA Server 2004 unloads web filters with ISAPI filter version higher than 6
		//Cannot load an application filter Web Proxy Filter ({4CB7513E-220E-4C20-815A-B67BAA295FF4}). FilterInit failed with code 0x80070057. To attempt to activate this application filter again, stop and restart the Firewall service. 
		pVer->dwFilterVersion = pVer->dwServerFilterVersion;
	}else{
		pVer->dwFilterVersion = HTTP_FILTER_REVISION;
	}
	return TRUE;
}

DWORD CISAPIFilter::OnReadRawData(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pRawData)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
DWORD CISAPIFilter::OnPreprocHeaders(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
DWORD CISAPIFilter::OnAuthentication(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_AUTHENT pAuthent)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
DWORD CISAPIFilter::OnUrlMap(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_URL_MAP pUrlMap)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
DWORD CISAPIFilter::OnSendRawData(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pRawData)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
DWORD CISAPIFilter::OnLog(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_LOG pLog)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
DWORD CISAPIFilter::OnEndOfNetSession(PHTTP_FILTER_CONTEXT pfc)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
DWORD CISAPIFilter::OnEndOfRequest(PHTTP_FILTER_CONTEXT pfc)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
DWORD CISAPIFilter::OnAuthComplete(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_AUTH_COMPLETE_INFO pAuthComplInfo)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
DWORD CISAPIFilter::OnSendResponse(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
DWORD CISAPIFilter::OnAccessDenied(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_ACCESS_DENIED)
{
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}

//ISAPI extended functionality
CString CISAPIFilter::GetServerVariable(PHTTP_FILTER_CONTEXT pfc,LPTSTR sv)
{
	/*
	 * This function will retrieve a server variable.
	 * Function starts with a buffer of MIN_HEADER_SIZE if this buffer is too
	 * small it will try again with the size the web server gave us, or if no
	 * size in indicated, try with a buffer of MAX_HEADER_SIZE
	 */
	DWORD bufsize = MIN_HEADER_SIZE;
	char buf[MIN_HEADER_SIZE]="";
    
	//get header value with MIN_HEADER_SIZE (average minimum header size)
	if(pfc->GetServerVariable(pfc,sv,buf,&bufsize)){
		for(DWORD i=0;i<bufsize-1;i++){	//replace all embedded nulls with space
			if(buf[i]=='\0') buf[i]=' ';
		}
		buf[bufsize-1]='\0';			//it should be null terminated already, but make sure it is. You never know!
		return CString(buf);
	}else{
		switch(GetLastError()){
			case ERROR_INSUFFICIENT_BUFFER:{	//if the buffer was too small, try again with value set by web server in bufsize
				CString tmp;				
				char* buf2 = new char[bufsize];
				if(buf2==NULL){
					tmp = "Error retrieving server variable";
				}else{
					if(pfc->GetServerVariable(pfc,sv,buf2,&bufsize)){
						for(DWORD i=0;i<bufsize-1;i++){	//replace all embedded nulls with space
							if(buf2[i]=='\0') buf2[i]=' ';
						}
						buf2[bufsize-1]='\0';	//it should be null terminated already, but make sure it is. You never know!
						tmp=buf2;
					}else{
						tmp="Error retrieving server variable"; //some error occured
					}
					delete[] buf2;
				}
				return tmp;
				break;
			}
			case ERROR_MORE_DATA: //buffer was too small, but no size set in bufsize, try again with MAX_HEADER_SIZE
				bufsize = MAX_HEADER_SIZE;
				char buf2[MAX_HEADER_SIZE];
				if(pfc->GetServerVariable(pfc,sv,buf2,&bufsize)){
					for(DWORD i=0;i<bufsize-1;i++){	//replace all embedded nulls with space
						if(buf2[i]=='\0') buf2[i]=' ';
					}
					buf2[bufsize-1]='\0';	//it should be null terminated already, but make sure it is. You never know!
					return CString(buf2);
				}else{
					return "Error retrieving server variable"; //some error occured
				}
				break;
			default:
				return ""; //variable is not present or some other error occured
				break;
		}
	}
}

CString CISAPIFilter::GetHeader(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pHeaders, char* h)
{
	/*
	 * This function will retrieve a header value.
	 * Function starts with a buffer of MIN_HEADER_SIZE if this buffer is too
	 * small it will try again with the size the web server gave us, or if no
	 * size in indicated, try with a buffer of MAX_HEADER_SIZE
	 */
	DWORD bufsize = MIN_HEADER_SIZE;
	char buf[MIN_HEADER_SIZE]="";
    
	//get header value with MIN_HEADER_SIZE (average minimum header size)
	if(pHeaders->GetHeader(pfc,h,buf,&bufsize)){
		for(DWORD i=0;i<bufsize-1;i++){	//replace all embedded nulls with space
			if(buf[i]=='\0') buf[i]=' ';
		}
		buf[bufsize-1]='\0';			//it should be null terminated already, but make sure it is. You never know!
		return CString(buf);
	}else{
		switch(GetLastError()){
			case ERROR_INSUFFICIENT_BUFFER:{	//if the buffer was too small, try again with value set by web server in bufsize
				CString tmp;				
				char* buf2 = new char[bufsize];
				if(buf2==NULL){
					tmp = "Error retrieving header";
				}else{
					if(pHeaders->GetHeader(pfc,h,buf2,&bufsize)){
						for(DWORD i=0;i<bufsize-1;i++){	//replace all embedded nulls with space
							if(buf2[i]=='\0') buf2[i]=' ';
						}
						buf2[bufsize-1]='\0';	//it should be null terminated already, but make sure it is. You never know!
						tmp=buf2;
					}else{
						tmp="Error retrieving header"; //some error occured
					}
					delete[] buf2;
				}
				return tmp;
				break;
			}
			case ERROR_MORE_DATA: //buffer was too small, but no size set in bufsize, try again with MAX_HEADER_SIZE
				bufsize = MAX_HEADER_SIZE;
				char buf2[MAX_HEADER_SIZE];
				if(pHeaders->GetHeader(pfc,h,buf2,&bufsize)){
					for(DWORD i=0;i<bufsize-1;i++){	//replace all embedded nulls with space
						if(buf2[i]=='\0') buf2[i]=' ';
					}
					buf2[bufsize-1]='\0';	//it should be null terminated already, but make sure it is. You never know!
					return CString(buf2);
				}else{
					return "Error retrieving header"; //some error occured
				}
				break;
			default:
				return ""; //header is not present or some other error occured
				break;
		}
	}
}

bool CISAPIFilter::ChangeHeader(CString& RawData, LPCTSTR Header, LPCTSTR Value, bool RemoveHeader)
{
	int maxheader; int poscr;
	maxheader = RawData.Find(CRLFCRLF);				//maximum size header
	int length = RawData.GetLength();

	if(maxheader!=-1 && maxheader<MAX_HEADER_SIZE){	//only if end of headers are found
		CString headers = RawData.Left(maxheader);	//only look at the headers
		int pos = headers.Find(Header);				//position header

		if(pos!=-1){								//double CRLF is in header?
			CString preh = RawData.Left(pos);		//copy everything before header
			RawData = RawData.Mid(pos,length-pos);
			poscr = RawData.Find(CRLF);				//end of header

			if(poscr!=-1){							//if end is found
				CString posth(RawData.Mid(poscr+2,length-poscr-2));

				//copy everything after header
				RawData = preh;

				//change header or remove it (remove has priority)
				if (!RemoveHeader){			//it really has to be '!' :)
					RawData += Header;
					RawData += " ";
					RawData += Value;
					RawData += CRLF;
				}
				//append rest of raw data after removed/altered header
				RawData += posth;

				return true;
			}else{
				RawData = "WARNING: Error adjusting '";
				RawData += Header;
				RawData += "' header (could not find end of header)";
				return false;
			}
		}else{
			RawData = "WARNING: Error adjusting '";
			RawData += Header;
			RawData += "' header (header is outside of MAX_HEADER_SIZE or no header found)";
			return false;
		}
	}else{
		RawData = "WARNING: Error adjusting '";
		RawData += Header;
		RawData += "' header (could not determine end of headers)";
		return false;
	}
}

bool CISAPIFilter::ChangeHeader(CString& RawData, CMapStringToString& map)
{
	int maxheader; int startcr;
	POSITION pos; CString Header; CString Value;
	pos = map.GetStartPosition();
	while(pos!=NULL){
		map.GetNextAssoc(pos,Header,Value);

		maxheader = RawData.Find(CRLFCRLF);				//maximum size header
		int length = RawData.GetLength();
		if(maxheader!=-1 && maxheader<MAX_HEADER_SIZE){	//only if end of headers are found
			CString headers = RawData.Left(maxheader);	//only look at the headers
			int start = headers.Find(Header);				//position header

			if(start!=-1){								//double CRLF is in header?
				CString preh = RawData.Left(start);		//copy everything before header
				RawData = RawData.Mid(start,length-start);
				startcr = RawData.Find(CRLF);				//end of header

				if(startcr!=-1){							//if end is found
					CString startth(RawData.Mid(startcr+2,length-startcr-2));

					//copy everything after header
					RawData = preh;

					//change header or remove it
					if (Value!=""){
						RawData += Header;
						RawData += " ";
						RawData += Value;
						RawData += CRLF;
					}
					//append rest of raw data after removed/altered header
					RawData += startth;

				}else{
					RawData = "WARNING: Error adjusting '";
					RawData += Header;
					RawData += "' header (could not find end of header)";
					return false;
				}
			}else{
				//header not present, add the header
				if (Value!=""){
					CString insert = CRLF;
					insert += Header;
					insert += " ";
					insert += Value;
					RawData.Insert(maxheader,insert);
				}
			}
		}else{
			RawData = "WARNING: Error adjusting '";
			RawData += Header;
			RawData += "' header (could not determine end of headers)";
			return false;
		}
	}
	return true;
}

bool CISAPIFilter::ChangeHeader(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE pResponse, CMapStringToString& map)
{
	POSITION pos; CString Header; CString Value;
	pos = map.GetStartPosition();
	while(pos!=NULL){
		map.GetNextAssoc(pos,Header,Value);
		if(Value.GetLength()==0){
			pResponse->SetHeader(pfc,Header.GetBuffer(0),"\0");
		}else{
			pResponse->SetHeader(pfc,Header.GetBuffer(0),Value.GetBuffer(0));
		}
	}
	return true;
}

void CISAPIFilter::PrepareRawData(PHTTP_FILTER_CONTEXT pfc, CString& RawData, CString& Headers, CString& Data)
{
	if(pfc->pFilterContext == CONTEXT_NEW_REQUEST || 
		pfc->pFilterContext == CONTEXT_SLOW_HEADER || 
		pfc->pFilterContext == CONTEXT_SLOW_HEADER_SKIP_ONE){	//new request / not all headers received?

		int maxheader = RawData.Find(CRLFCRLF);	//maximum size header
	
		if(maxheader!=-1){						//if end of headers are found (if not, raw data is not complete!)
			Headers = RawData.Left(maxheader);			//only headers
			//ignore the request line (!= header)
			int starth = Headers.Find(CRLF);
			if (starth==-1){
				Headers = "";						//no headers (only request line)!
			}else{
				Headers = Headers.Right(Headers.GetLength()-starth-2);
			}
			Data = RawData.Right(RawData.GetLength()-maxheader-4);//only look at the body
			//mark request (all headers received)
			pfc->pFilterContext = CONTEXT_HEADERS_RECEIVED;
		}else{
			//logger.Append("WARNING: Could not determine end of headers, will process all data as headers");
			Headers = RawData;
			//if double crlf was between events, process this as data as well
			if(RawData.Left(1)==CR || RawData.Left(1)==LF){
				//logger.Append("WARNING: Raw data starts with <CR> or <LF>, so this is probably data part and not headers. Will process it as data as well!");
				Data = RawData;
			}
		}

	}else{	//is additional data
		Data = RawData;
	}	
}

CString CISAPIFilter::SerializeRequest(PHTTP_FILTER_CONTEXT pfc)
{
	CString qs = GetServerVariable(pfc,"QUERY_STRING");
	if(qs!=""){
		qs = "?" + qs;
	}
	return GetServerVariable(pfc,"REQUEST_METHOD") + " " + GetServerVariable(pfc,"URL") + qs + " " + GetServerVariable(pfc,"SERVER_PROTOCOL") + CRLF + GetServerVariable(pfc,"ALL_RAW") + CRLF + CRLF;
}

bool CISAPIFilter::IsIIS7ProblemResponse(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE pResponse)
{
	CString ContentType = GetHeader(pfc,pResponse,"Content-Type:");

	if(
			/* PDF/MP3/MP4... Partial Content issue */
			(ContentType.Left(5)!="text/" && GetServerVariable(pfc,"HTTP_RANGE") != "") ||
			/* download 256MiB or larger file issue (zip, rar...) on IIS 7.x */
			(ContentType == "application/x-zip-compressed" || ContentType == "application/octet-stream")

			//TODO: 4.x - maybe only scan text content types (+ empty content types) in OnSendRawData
			//https://blogs.msdn.microsoft.com/david.wang/2005/12/14/how-iis6-compression-schemes-interact-with-isapi-filters/

		){
		return true;
	}
	return false;
}

bool CISAPIFilter::IsWebsocketsUpgrade(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE pResponse)
{
	if(pResponse->HttpStatus==101){ //HTTP/1.1 101 Switching Protocols
		CString Upgrade = GetHeader(pfc,pResponse,"Upgrade:");
		return Upgrade == "Websocket";
	}
	return false;
}

void CISAPIFilter::SendData(PHTTP_FILTER_CONTEXT pfc, CString& Response)
{
	DWORD szbuf(Response.GetLength());
	//pfc->WriteClient(Response.GetBuffer(0),&szbuf); //this crashes ForeFront TMG 2010 (pfc was CHttpFilterContext*)
	pfc->WriteClient(pfc, Response.GetBuffer(0),&szbuf, 0);
}