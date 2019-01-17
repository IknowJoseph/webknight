#pragma once
//
//  base64 encoding and decoding with C++.
//  Version: 1.01.00
//

#include <string>

class CBase64
{
public:
	static CString Encode(CString s);
	static CString Encode(unsigned char const* , unsigned int len);
	static CString Decode(CString s);

	CBase64(void);
	~CBase64(void);
};