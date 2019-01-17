'
'setntfs.vbs
'Script for adding IIS permissions on WebKnight folder
'
Option Explicit

Dim FilterPath, Username, par

FilterPath = Session.Property("WEBKNIGHTDIR")
Username = Session.Property("USERNAME")
If FilterPath="" Then
	par = Split(Session.Property("CustomActionData"),"|")
	Username = par(0)
	FilterPath = par(1)
End If

On Error Resume Next
If Username<>"" Then
	SetNTFSPermission FilterPath, Username,"C"
End If
'SetNTFSPermission FilterPath, "IIS_WPG","C" 'for IIS6, but it is not working?
SetNTFSPermission FilterPath, "NETWORK SERVICE","C" 'IIS6
SetNTFSPermission FilterPath, "IIS_IUSRS","C" 'IIS7
SetNTFSPermission FilterPath, "IUSR","C" 'needed for admin /WebKnight/default.asp
On Error Goto 0

Sub SetNTFSPermission(Path,Username,Permission)
	'http://www.experts-exchange.com/Programming/Installation/InstallShield/Q_24315443.html
	If Right(Path,1) = "\" Then Path = Left(Path,Len(Path)-1)
	'MsgBox "cacls.exe """ & Path & """ /T /E /C /G """ & Username & """:" & Permission,,"Command"
	CreateObject("WScript.Shell").run "cacls.exe """ & Path & """ /T /E /C /G """ & Username & """:" & Permission
End Sub


