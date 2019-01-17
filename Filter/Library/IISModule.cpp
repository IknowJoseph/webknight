/*
    AQTRONIX C++ Library
    Copyright 2014-2015 Parcifal Aertssen

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
// IISModule.cpp: implementation of the CIISModule class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "IISModule.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CIISModule::CIISModule():m_hEventLog(NULL)
{
	// Open a handle to the Event Log.
    m_hEventLog = RegisterEventSource(NULL,"IISADMIN");
}

CIISModule::~CIISModule()
{
	//// Test whether the handle for the Event Log is open.
    if (NULL != m_hEventLog){
        // Close the handle to the Event Log.
        DeregisterEventSource(m_hEventLog);
        m_hEventLog = NULL;
    }
}

VOID CIISModule::Terminate()
{
    // Remove the class from memory.
    delete this;
}

HRESULT CIISModule::SendPage(IHttpContext* pHttpContext, PCSTR Text)
{
	HRESULT hr = S_FALSE;
	IHttpResponse * pHttpResponse = pHttpContext->GetResponse();
	if(pHttpResponse != NULL){
		//clear response
        pHttpResponse->Clear();
		//send chunk
		hr = WriteClient(pHttpContext,Text);
	}
	return hr;
}

HRESULT CIISModule::WriteClient(IHttpContext* pHttpContext, PCSTR Text)
{
	HRESULT hr = S_FALSE;
	IHttpResponse * pHttpResponse = pHttpContext->GetResponse();
	if(pHttpResponse != NULL){
		//send chunk
		HTTP_DATA_CHUNK data;
		size_t size = strlen(Text);
        data.DataChunkType = HttpDataChunkFromMemory;
		data.FromMemory.BufferLength = size;
        data.FromMemory.pBuffer = pHttpContext->AllocateRequestMemory(size+1);
		if(!data.FromMemory.pBuffer){
			hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		}else{
			char *p = static_cast<char *>(data.FromMemory.pBuffer);
			strcpy_s(p, size+1, Text);
			hr = pHttpResponse->WriteEntityChunkByReference(&data, -1);
		}
	}
	return hr;
}

CString CIISModule::GetRawDataWebKnight42(IN IPreBeginRequestProvider * pProvider, IHttpRequest* pHttpRequest)
{
	//source: https://msdn.microsoft.com/en-us/library/ms694041%28v=vs.90%29.aspx

	// Create an HRESULT to receive return values from methods.
    HRESULT hr;

    // Create a data chunk.
    HTTP_DATA_CHUNK dataChunk;
    // Set the chunk to a chunk in memory.
    dataChunk.DataChunkType = HttpDataChunkFromMemory;

    // Allocate a buffer.
	const DWORD cbBufferSize = 1024;
    DWORD cbBytesReceived = cbBufferSize;
	void * pvRequestBody = pProvider->GetHttpContext()->AllocateRequestMemory(cbBufferSize);
	CString data("");

    // Test for an error.
    if (NULL == pvRequestBody)
    {
        // Set the error status.
        hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
        pProvider->SetErrorStatus( hr );
        // End additional processing.
        return data;
    }

    // Loop through the request entity.
    while (cbBytesReceived==cbBufferSize) //don't use GetRemainingEntityBytes (see bugs in IIS)
    {
        // Retrieve the request body.
        hr = pHttpRequest->ReadEntityBody(pvRequestBody,cbBufferSize,false,&cbBytesReceived,NULL);

        // Test for an error.
        if (FAILED(hr))
        {
            // End of data is okay.
            if (ERROR_HANDLE_EOF != (hr  & 0x0000FFFF))
            {
                // Set the error status.
                pProvider->SetErrorStatus( hr );
			}else{
				dataChunk.FromMemory.pBuffer = pvRequestBody;
				dataChunk.FromMemory.BufferLength = cbBytesReceived;
				data += CStringHelper::ConvertBinaryData((BYTE*)pvRequestBody,cbBytesReceived,' ');
			}
            // End additional processing.
            return data;
        }
        dataChunk.FromMemory.pBuffer = pvRequestBody;
        dataChunk.FromMemory.BufferLength = cbBytesReceived;
		data += CStringHelper::ConvertBinaryData((BYTE*)pvRequestBody,cbBytesReceived,' ');
    }

	return data;
}

CString CIISModule::GetRawData(IN IPreBeginRequestProvider * pProvider, IHttpRequest* pHttpRequest)
{
	//source: https://msdn.microsoft.com/en-us/library/ms694041%28v=vs.90%29.aspx

	// Create an HRESULT to receive return values from methods.
    HRESULT hr;
	IHttpContext* pHttpContext = pProvider->GetHttpContext();
	void* pvRequestBody = NULL;

	CHttpDataChunks chunks;

    // Allocate a buffer.
	DWORD cbBufferSize = pHttpRequest->GetRemainingEntityBytes(); //can be 0 (multipart/form-data with file upload)
	if(cbBufferSize==0){
		cbBufferSize = 1024; //not larger than 16384 (ReadEntityBody max chunk size)
	}

    DWORD cbBytesReceived = 0;
	bool isEOS = false;
	
    // Loop through the request entity.
    while (!isEOS) //don't use GetRemainingEntityBytes (see bugs in IIS)
    {
		pvRequestBody = pHttpContext->AllocateRequestMemory(cbBufferSize);
		
		// Test for an error.
		if (NULL == pvRequestBody)
		{
			// Set the error status.
			hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
			pProvider->SetErrorStatus( hr );
			// End additional processing.
			break;
		}

		// Retrieve the request body.
		hr = pHttpRequest->ReadEntityBody(pvRequestBody,cbBufferSize,false,&cbBytesReceived,NULL);

        // Test for an error.
        if (FAILED(hr))
        {
            // End of data is okay.
            if (ERROR_HANDLE_EOF != (hr  & 0x0000FFFF))
            {
                // Set the error status.
                pProvider->SetErrorStatus( hr );
			}
			break;
        }

		chunks.Add(pvRequestBody,cbBytesReceived);

		if(cbBytesReceived==cbBufferSize){
			DWORD next = pHttpRequest->GetRemainingEntityBytes();
			if(next!=0){
				cbBufferSize = next;
			}else{
				if(cbBufferSize<1024*1024) /* 1MB max buffer */
					cbBufferSize *= 2; //next time read bigger chunk
			}
		}else{
			isEOS = true; //TODO: MODULE - this will probably break file uploads, since the upload is still happening here (not all chunks received)
		}
    }

	CString data = chunks.ToString();

	//restore entity
	int count = chunks.GetCount();
	if(count>0){
		if(count>1){
			//restore multiple chunks - merge them
			ULONG totalsize = chunks.GetByteCount();

			void* pEntity = pHttpContext->AllocateRequestMemory((DWORD)totalsize);
			// Test for an error.
			if (NULL == pvRequestBody)
			{
				// Set the error status.
				hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
				pProvider->SetErrorStatus( hr );
			}else{
				chunks.Merge(pEntity);
				pHttpRequest->InsertEntityBody(pEntity,totalsize);
			}
		}else{
			//restore single chunk
			HTTP_DATA_CHUNK* pChunk = (HTTP_DATA_CHUNK*)chunks.GetAt(chunks.GetHeadPosition());
			pHttpRequest->InsertEntityBody(pChunk->FromMemory.pBuffer,pChunk->FromMemory.BufferLength);
		}
	}

	chunks.Clear();

	return data;
}

CString CIISModule::GetHeader(IHttpContext* pHttpContext, PCSTR Header /* without trailing ':' */)
{
    // Buffers to store the returned header value.
    PCSTR pszHeader;

    // Length of the returned header value.
    USHORT cchHeader;

    // Retrieve a pointer to the request.
    IHttpRequest * pHttpRequest = pHttpContext->GetRequest();

    // Test for an error.
    if (pHttpRequest != NULL)
    {
        // Get the lengh of the header.
        pszHeader = pHttpRequest->GetHeader(Header,&cchHeader);

        // The header length will be 0 if the header was not found.
		if (cchHeader == 0 || pszHeader==NULL){
			return "";
		}else{
			return pszHeader;
        }
    }
	return "";
}

CString CIISModule::GetServerVariable(IHttpContext* pHttpContext, PCSTR Variable)
{
    // Buffers to store the returned value.
    PCSTR pszValue;

    // Length of the returned value.
    DWORD cchValue;

    // Get the lengh of the variable.
    if(FAILED(pHttpContext->GetServerVariable(Variable, &pszValue, &cchValue)))
		return "";

    // The header length will be 0 if the variable was not found.
	if (cchValue == 0 || pszValue==NULL){
		return "";
	}else{
		return pszValue;
    }

	return "";
}

BOOL CIISModule::WriteEventLog(LPCSTR szNotification)
{
	return WriteEventLog(szNotification, EVENTLOG_INFORMATION_TYPE, 0, 0);
}

void CIISModule::Error(LPCTSTR Message)
{
	WriteEventLog(Message,EVENTLOG_ERROR_TYPE,0,0);
}

BOOL CIISModule::WriteEventLog(LPCSTR szNotification, WORD wType, WORD wCategory, DWORD dwEventID)
{
    // Test whether the handle for the Event Viewer is open.
    if (NULL != m_hEventLog)
    {
        // Write any strings to the Event Viewer and return.
        return ReportEvent(m_hEventLog, wType, wCategory, dwEventID, NULL, 1, 0, &szNotification, NULL);
    }
    return FALSE;
}