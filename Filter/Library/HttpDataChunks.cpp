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
// ProcessHelper.cpp: implementation of the CProcessHelper class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#include "HttpDataChunks.h"

CHttpDataChunks::CHttpDataChunks(void)
{
}

CHttpDataChunks::~CHttpDataChunks(void)
{
	Clear();
}

void CHttpDataChunks::Add(void* pBuffer, DWORD size)
{
	HTTP_DATA_CHUNK* pChunk = new HTTP_DATA_CHUNK();
	pChunk->DataChunkType = HttpDataChunkFromMemory;
	pChunk->FromMemory.BufferLength = size;
	pChunk->FromMemory.pBuffer = pBuffer;
	this->AddTail(pChunk);
}

void CHttpDataChunks::Clear()
{
	POSITION pos = this->GetHeadPosition();
	while(pos!=NULL){
		delete (HTTP_DATA_CHUNK*)this->GetNext(pos);
	}
	this->RemoveAll();
}

ULONG CHttpDataChunks::GetByteCount()
{
	ULONG totalsize = 0;
	POSITION pos = this->GetHeadPosition();
	while(pos!=NULL){
		HTTP_DATA_CHUNK* pChunk = (HTTP_DATA_CHUNK*)this->GetNext(pos);
		totalsize += pChunk->FromMemory.BufferLength;
	}
	return totalsize;
}

void CHttpDataChunks::Merge(void* destination)
{
	POSITION pos = this->GetHeadPosition();
	ULONG offset = 0;
	while(pos!=NULL){
		HTTP_DATA_CHUNK* pChunk = (HTTP_DATA_CHUNK*)this->GetNext(pos);
		memcpy(((char*)destination) + offset,pChunk->FromMemory.pBuffer,pChunk->FromMemory.BufferLength);
		offset += pChunk->FromMemory.BufferLength;
	}
}

CString CHttpDataChunks::ToString()
{
	CString data("");
	POSITION pos = this->GetHeadPosition();
	while(pos!=NULL){
		HTTP_DATA_CHUNK* pChunk = (HTTP_DATA_CHUNK*)this->GetNext(pos);
		data += CStringHelper::ConvertBinaryData((BYTE*)pChunk->FromMemory.pBuffer,pChunk->FromMemory.BufferLength,' ');
	}
	return data;
}
