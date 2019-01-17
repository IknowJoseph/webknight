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
// ISAPIExtension.cpp: implementation of the CISAPIExtension class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ISAPIExtension.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CISAPIExtension::CISAPIExtension()
{

}

CISAPIExtension::~CISAPIExtension()
{

}

BOOL CISAPIExtension::GetExtensionVersion(HSE_VERSION_INFO *pVer)
{
	pVer->dwExtensionVersion = HSE_VERSION;
    return TRUE;
}

DWORD CISAPIExtension::HttpExtensionProc(EXTENSION_CONTROL_BLOCK *pECB)
{
	SendResponse(pECB,"Default implementation of CISAPIExtension class");
	return HSE_STATUS_SUCCESS;
}

BOOL CISAPIExtension::TerminateExtension(DWORD dwFlags)
{
    return TRUE;
}

CString CISAPIExtension::GetServerVariable(EXTENSION_CONTROL_BLOCK *pECB,LPTSTR sv)
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
	if(pECB->GetServerVariable(pECB->ConnID,sv,buf,&bufsize)){
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
					if(pECB->GetServerVariable(pECB->ConnID,sv,buf2,&bufsize)){
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
				if(pECB->GetServerVariable(pECB->ConnID,sv,buf2,&bufsize)){
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

void CISAPIExtension::SendResponse(EXTENSION_CONTROL_BLOCK* pECB, CString Message)
{
	DWORD size = (DWORD) Message.GetLength();
	pECB->WriteClient(pECB->ConnID, Message.GetBuffer(0),&size,NULL);
}

CString CISAPIExtension::GetRawData(EXTENSION_CONTROL_BLOCK* pECB)
{
	//TODO: ISAPI EXTENSION - ReadClient DoS (60 sec timeout) -> Async (read outside CSingleLock)
	//return only prefetched data
	return CStringHelper::ConvertBinaryData((BYTE*)pECB->lpbData,pECB->cbAvailable,' ');

	if(pECB->cbAvailable < pECB->cbTotalBytes && pECB->cbTotalBytes < 0xffffffff /* don't process chunked encoding */){
		//http://www.sc.ehu.es/scrwwwsr/isapi/ch08.htm

		//use isapitools.h from sdk (inc & src folder:)
		//C:\Program Files\Microsoft Platform SDK\Samples\Web\iis\ISAPI_6.0

		// Start processing of input information here.
		BYTE* lpszTemp = (BYTE*)LocalAlloc(LPTR, pECB->cbTotalBytes);
		if( NULL == lpszTemp )
			return "Error";

		if(pECB->cbAvailable>0)
			memcpy(lpszTemp, pECB->lpbData, pECB->cbAvailable);

		DWORD cbQuery = pECB->cbTotalBytes - pECB->cbAvailable;
		pECB->lpbData = lpszTemp;

		/*
		int countSlow = -1;
		if(Settings.Global.SlowPostAttack && GetServerVariable(pfc,"REQUEST_METHOD")=="POST")
			countSlow = 0;
		CString ContentLength = GetServerVariable(pfc,"HTTP_CONTENT_LENGTH");
		*/

		while( cbQuery > 0 )
		{
			if(pECB->ReadClient(pECB->ConnID,(LPVOID)(lpszTemp + pECB->cbAvailable),&cbQuery) == FALSE)
				return CStringHelper::ConvertBinaryData(lpszTemp,pECB->cbAvailable,' '); //return total read bytes

			if(cbQuery==0) //connection closed
				return CStringHelper::ConvertBinaryData(lpszTemp,pECB->cbAvailable,' '); //return total read bytes

			//TODO: ISAPI EXTENSION - Slow POST detection?
			/*
			if(countSlow>-1 && cbQuery<100){
				if(ContentLength.GetLength()>2){
					countSlow++;
					if(countSlow>20){
						action.Set(Settings.Global.SlowPostAttack);
						Alert("Slow POST attack detected (" + CStringHelper::Safe_DWORDToAscii(cbQuery) + " bytes received of Content-Length: " + ContentLength.Left(23) + ")",Settings.Global.SlowPostAttack);
						countSlow = -1;
					}
				}
			}//*/

			pECB->cbAvailable += cbQuery;
			cbQuery = pECB->cbTotalBytes - pECB->cbAvailable;
		}

		return CStringHelper::ConvertBinaryData(lpszTemp,pECB->cbAvailable,' '); //return available bytes

	}else{
		return CStringHelper::ConvertBinaryData((BYTE*)pECB->lpbData,pECB->cbAvailable,' ');
	}

	return "";
}
