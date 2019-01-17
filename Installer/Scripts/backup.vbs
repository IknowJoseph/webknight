'
'Backup script for WebKnight MSI
'Script for backing up the WebKnight settings
'
Option Explicit

Dim FilterName
Dim FilterPath

FilterName = "WebKnight"

FilterPath = Session.Property("WEBKNIGHTDIR")
If FilterPath = "" Then
	FilterPath = Session.Property("CustomActionData")
End If

Dim fso
Set fso = CreateObject("Scripting.FileSystemObject")

'Upgrade "WebKnight.xml","Backup.xml","Upgrade.xml" 'no longer needed, done by UpgradeSettings
UpgradeSettings "WebKnight.","xml"

Set fso = Nothing

Sub Upgrade(FilterSettingsName,BackupSettingsName,UpgradeSettingsName)
	On Error Resume Next
	fso.DeleteFile FilterPath & BackupSettingsName
	Err.Clear
	fso.DeleteFile FilterPath & UpgradeSettingsName
	Err.Clear
	'backup settings file
	fso.CopyFile FilterPath & FilterSettingsName,FilterPath & BackupSettingsName
	If Err Then
		MsgBox "There was an error backing up your settings file " & FilterSettingsName & ":" & Err.Description,,FilterName
	Else
		'MsgBox "Your previous settings were backed up to the file: '" & BackupSettingsName & "'. " & vbCRLF & vbCRLF & "This installation comes with new default settings and you can find these in the file '" & FilterSettingsName & "'. If you want to continue using your previous setting delete this file and rename the file '" & BackupSettingsName & "' to '" & FilterSettingsName & "' after the installation.",,FilterName
	End If
	'upgrade file (this file will be upgraded by WebKnight)
	fso.MoveFile FilterPath & FilterSettingsName,FilterPath & UpgradeSettingsName
	On Error Goto 0
End Sub

Sub UpgradeSettings(Prefix,Extension)
	On Error Resume Next
	Dim folder, file, fn, bare, length
	length = Len(Prefix)
	Set folder = fso.GetFolder(FilterPath)
	For Each file in folder.Files
		fn = fso.GetFileName(file)
		If fso.GetExtensionName(fn) = Extension And Left(fn,length) = Prefix Then
			bare = Mid(fn,length + 1)
			Upgrade fn,"Backup." & bare,"Upgrade." & bare
		End If
	Next
	Set folder = Nothing
	On Error Goto 0
End Sub

