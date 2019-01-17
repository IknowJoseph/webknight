#pragma once
#include "afx.h"

class CSandboxFile : public CFile
{
	DECLARE_DYNAMIC(CSandboxFile)

protected:
#if _MSC_VER >= 1400 // VS 8.0
	void _AfxFillExceptionInfo(CFileException* pException,LPCTSTR lpszFileName);
	BOOL _AfxFullPath2(_Out_z_cap_c_(_MAX_PATH) LPTSTR lpszPathOut, LPCTSTR lpszFileIn, CFileException* pException);
	void AfxGetRoot(LPCTSTR lpszPath, CString& strRoot);
#endif

public:
#if _MSC_VER >= 1400 // VS 8.0
	virtual BOOL Open(LPCTSTR lpszFileName, UINT nOpenFlags, CFileException* pError = NULL);
#endif

	CSandboxFile(void);
	CSandboxFile(HANDLE hFile);
	CSandboxFile(LPCTSTR lpszFileName, UINT nOpenFlags);

	~CSandboxFile(void);
};
