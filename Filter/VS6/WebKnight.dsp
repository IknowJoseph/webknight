# Microsoft Developer Studio Project File - Name="WebKnight" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=WebKnight - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "WebKnight.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "WebKnight.mak" CFG="WebKnight - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "WebKnight - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "WebKnight - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "WebKnight - Win32 Release"

# PROP BASE Use_MFC 1
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 1
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\Release"
# PROP Intermediate_Dir "..\Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_WINDLL" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_WINDLL" /D "_USRDLL" /Yu"stdafx.h" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x813 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 /nologo /subsystem:windows /dll /machine:I386
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "WebKnight - Win32 Debug"

# PROP BASE Use_MFC 1
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 1
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_WINDLL" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MTd /W4 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_WINDLL" /D "_USRDLL" /Yu"stdafx.h" /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x813 /d "_DEBUG"
# ADD RSC /l 0x813 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "WebKnight - Win32 Release"
# Name "WebKnight - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\Library\Action.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\ExploitScan.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\Validation.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\ValidationScan.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\FormsAuthenticationScan.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\FileName.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\FileStamp.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\SandboxFile.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\HttpDataChunks.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\Firewall.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\FirewallSettings.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\HTTPFirewall.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\HTTPFirewallSettings.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\IPRangeTemplate.h
# End Source File
# Begin Source File

SOURCE=..\Library\IPRangeList.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\IISModule.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\ISAPIExtension.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\ISAPIFilter.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\ISAPIFirewall.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\WebAdmin.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\Signatures.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\BlockList.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\BlockListCollection.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\ParameterSettings.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\HeaderValidation.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\ExperimentalSettings.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\LogFile.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\Logger.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\ODBCConnection.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\SyslogDevice.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\SyslogSocket.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\ProcessHelper.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\RegexCache.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\Settings.cpp
# End Source File
# Begin Source File

SOURCE=..\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# Begin Source File

SOURCE=..\Library\StringCache.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\StringHelper.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\Unicode.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\URL.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\DataUrl.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\MIME.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\Base64.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\HTML.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\WebAgents.cpp
# End Source File
# Begin Source File

SOURCE=..\WebKnight.cpp
# End Source File
# Begin Source File

SOURCE=..\WebKnight.def
# End Source File
# Begin Source File

SOURCE=..\WebKnight.rc
# End Source File
# Begin Source File

SOURCE=..\WebKnightAdmin.cpp
# End Source File
# Begin Source File

SOURCE=..\WebKnightExtension.cpp
# End Source File
# Begin Source File

SOURCE=..\WebKnightFilter.cpp
# End Source File
# Begin Source File

SOURCE=..\WebKnightModule.cpp
# End Source File
# Begin Source File

SOURCE=..\WebKnightSettings.cpp
# End Source File
# Begin Source File

SOURCE=..\WebKnightUpgrade.cpp
# End Source File
# Begin Source File

SOURCE=..\WebApplications.cpp
# End Source File
# Begin Source File

SOURCE=..\Library\XML.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\Library\Action.h
# End Source File
# Begin Source File

SOURCE=..\Library\ExploitScan.h
# End Source File
# Begin Source File

SOURCE=..\Library\Validation.h
# End Source File
# Begin Source File

SOURCE=..\Library\ValidationScan.h
# End Source File
# Begin Source File

SOURCE=..\Library\FormsAuthenticationScan.h
# End Source File
# Begin Source File

SOURCE=..\Library\FileName.h
# End Source File
# Begin Source File

SOURCE=..\Library\FileStamp.h
# End Source File
# Begin Source File

SOURCE=..\Library\SandboxFile.h
# End Source File
# Begin Source File

SOURCE=..\Library\HttpDataChunks.h
# End Source File
# Begin Source File

SOURCE=..\Library\Firewall.h
# End Source File
# Begin Source File

SOURCE=..\Library\FirewallSettings.h
# End Source File
# Begin Source File

SOURCE=..\Globals.h
# End Source File
# Begin Source File

SOURCE=..\Library\HTTPFirewall.h
# End Source File
# Begin Source File

SOURCE=..\Library\HTTPFirewallSettings.h
# End Source File
# Begin Source File

SOURCE=..\Library\IPAddress.h
# End Source File
# Begin Source File

SOURCE=..\Library\IPAddressTemplate.h
# End Source File
# Begin Source File

SOURCE=..\Library\IPRange.h
# End Source File
# Begin Source File

SOURCE=..\Library\IPRangeList.h
# End Source File
# Begin Source File

SOURCE=..\Library\IISModule.h
# End Source File
# Begin Source File

SOURCE=..\Library\ISAPIExtension.h
# End Source File
# Begin Source File

SOURCE=..\Library\ISAPIFilter.h
# End Source File
# Begin Source File

SOURCE=..\Library\ISAPIFirewall.h
# End Source File
# Begin Source File

SOURCE=..\Library\WebAdmin.h
# End Source File
# Begin Source File

SOURCE=..\Library\Signatures.h
# End Source File
# Begin Source File

SOURCE=..\Library\BlockList.h
# End Source File
# Begin Source File

SOURCE=..\Library\BlockListCollection.h
# End Source File
# Begin Source File

SOURCE=..\Library\ParameterSettings.h
# End Source File
# Begin Source File

SOURCE=..\Library\HeaderValidation.h
# End Source File
# Begin Source File

SOURCE=..\Library\ExperimentalSettings.h
# End Source File
# Begin Source File

SOURCE=..\Library\LogFile.h
# End Source File
# Begin Source File

SOURCE=..\Library\Logger.h
# End Source File
# Begin Source File

SOURCE=..\Library\ODBCConnection.h
# End Source File
# Begin Source File

SOURCE=..\Library\SyslogDevice.h
# End Source File
# Begin Source File

SOURCE=..\Library\SyslogSocket.h
# End Source File
# Begin Source File

SOURCE=..\Library\ProcessHelper.h
# End Source File
# Begin Source File

SOURCE=..\Resource.h
# End Source File
# Begin Source File

SOURCE=..\Library\RegexCache.h
# End Source File
# Begin Source File

SOURCE=..\Library\Settings.h
# End Source File
# Begin Source File

SOURCE=..\StdAfx.h
# End Source File
# Begin Source File

SOURCE=..\Library\StringCache.h
# End Source File
# Begin Source File

SOURCE=..\Library\StringHelper.h
# End Source File
# Begin Source File

SOURCE=..\Library\Unicode.h
# End Source File
# Begin Source File

SOURCE=..\Library\URL.h
# End Source File
# Begin Source File

SOURCE=..\Library\DataUrl.h
# End Source File
# Begin Source File

SOURCE=..\Library\MIME.h
# End Source File
# Begin Source File

SOURCE=..\Library\Base64.h
# End Source File
# Begin Source File

SOURCE=..\Library\HTML.h
# End Source File
# Begin Source File

SOURCE=..\Library\WebAgents.h
# End Source File
# Begin Source File

SOURCE=..\WebKnight.h
# End Source File
# Begin Source File

SOURCE=..\WebKnightAdmin.h
# End Source File
# Begin Source File

SOURCE=..\WebKnightExtension.h
# End Source File
# Begin Source File

SOURCE=..\WebKnightFilter.h
# End Source File
# Begin Source File

SOURCE=..\WebKnightModule.h
# End Source File
# Begin Source File

SOURCE=..\WebKnightSettings.h
# End Source File
# Begin Source File

SOURCE=..\WebKnightUpgrade.h
# End Source File
# Begin Source File

SOURCE=..\WebApplications.h
# End Source File
# Begin Source File

SOURCE=..\Library\XML.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=..\WebKnight.rc2
# End Source File
# End Group
# Begin Source File

SOURCE=..\Readme.txt
# End Source File
# End Target
# End Project
