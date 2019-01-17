'
'IISModule.vbs
'Script for adding/removing WebKnight in IIS as a module
'
Option Explicit

Dim HostName
Dim FilterName
Dim FilterPath
Dim FilterDesc
Dim Bitness

FilterName = "WebKnight"
FilterDesc = "Filter for securing IIS"
HostName = "LocalHost"				'uncomment this for unattended setup

FilterPath = "C:\Program Files\AQTRONIX WebKnight\"
Bitness = 64

RegisterIISModule FilterName,HostName,FilterPath
'UnRegisterIISModule FilterName, HostName

'-----------------------------------------------------------------
'                           IIS Install
'-----------------------------------------------------------------

Sub RegisterIISModule(FilterName,HostName,FilterPath)
	'Install
	RegisterIIS7Module FilterName,FilterPath,Bitness,FilterName & ".dll"
	If Bitness=64 Then 'for 32 bit app pools
		RegisterIIS7Module FilterName,FilterPath,"32",FilterName & ".32bit.dll"
	End If
End Sub

Sub RegisterIIS7Module(FilterName,FilterPath,Bitness,FilterDLLName)
    'install module using IIS7 API

    Dim AdminManager
    Dim ModulesSection
    Dim ModulesCollection
    Dim GlobalModulesSection
    Dim GlobalModulesCollection
    Dim AddElement
	
    Set AdminManager = CreateObject("Microsoft.ApplicationHost.WritableAdminManager")
    AdminManager.CommitPath = "MACHINE/WEBROOT/APPHOST"

	'register global module
	Set GlobalModulesSection = AdminManager.GetAdminSection("system.webServer/globalModules", "MACHINE/WEBROOT/APPHOST")
	Set GlobalModulesCollection = GlobalModulesSection.Collection

	Set AddElement = GlobalModulesCollection.CreateNewElement("add")
	AddElement.Properties.Item("name").Value = FilterName & " " & Bitness & "-bit"
	AddElement.Properties.Item("image").Value = FilterPath & FilterDLLName
	AddElement.Properties.Item("preCondition").Value = "bitness" & Bitness
	GlobalModulesCollection.AddElement AddElement
	
	AdminManager.CommitChanges()
	
	'add module	
	Set ModulesSection = AdminManager.GetAdminSection("system.webServer/modules", "MACHINE/WEBROOT/APPHOST")
	Set ModulesCollection = ModulesSection.Collection

	Set AddElement = ModulesCollection.CreateNewElement("add")
	AddElement.Properties.Item("name").Value = FilterName & " " & Bitness & "-bit"
	AddElement.Properties.Item("preCondition").Value = "bitness" & Bitness
	ModulesCollection.AddElement AddElement

	AdminManager.CommitChanges()
  
	'cleanup
	Set AddElement = Nothing
    Set ModulesCollection = Nothing
    Set ModulesSection = Nothing
    Set GlobalModulesCollection = Nothing
    Set GlobalModulesSection = Nothing
	Set AdminManager = Nothing

End Sub


'-----------------------------------------------------------------
'                         IIS  Uninstall
'-----------------------------------------------------------------

Sub UnRegisterIISModule(FilterName,HostName)
	'uninstall
	UnRegisterIIS7Module FilterName,FilterPath,Bitness,FilterName & ".dll"
	If Bitness=64 Then 'for 32 bit app pools
		UnRegisterIIS7Module FilterName,FilterPath,"32",FilterName & ".32bit.dll"
	End If

End Sub

Sub UnRegisterIIS7Module(FilterName,FilterPath,Bitness,FilterDLLName)
    'unregister module using IIS7 API
	On Error Resume Next 'gracefully uninstall
    Dim AdminManager
	Dim ModulesSection
	Dim ModulesCollection
    Dim GlobalModulesSection
    Dim GlobalModulesCollection
    Dim ElementPos
	
    Set AdminManager = CreateObject("Microsoft.ApplicationHost.WritableAdminManager")
    AdminManager.CommitPath = "MACHINE/WEBROOT/APPHOST"
	
	'remove module
    Set ModulesSection = AdminManager.GetAdminSection("system.webServer/modules", "MACHINE/WEBROOT/APPHOST")
    Set ModulesCollection = ModulesSection.Collection
    ElementPos = FindFilter(ModulesCollection,FilterName & " " & Bitness & "-bit","add","name")
    If ElementPos>-1 Then
        ModulesCollection.DeleteElement(ElementPos)
    End If

	'unregister global module
    Set GlobalModulesSection = AdminManager.GetAdminSection("system.webServer/globalModules", "MACHINE/WEBROOT/APPHOST")
    Set GlobalModulesCollection = GlobalModulesSection.Collection
    ElementPos = FindFilter(GlobalModulesCollection,FilterName & " " & Bitness & "-bit","add","name")
    If ElementPos>-1 Then
        GlobalModulesCollection.DeleteElement(ElementPos)
    End If

	AdminManager.CommitChanges()
	
    Set ModulesCollection = Nothing
    Set ModulesSection = Nothing	
    Set GlobalModulesCollection = Nothing
    Set GlobalModulesSection = Nothing	
    Set AdminManager = Nothing
End Sub

Function FindFilter(Collection,FilterName,TagKey,MatchAttribute)
    Dim element
    Dim i
    Dim count
    FindFilter = -1
    count = CLng(Collection.Count)
    For i=0 To count - 1
    	Set element = collection.Item(i)
    	If LCase(element.Name) = LCase(TagKey) Then
    		Dim n
    		Set n = element.GetPropertyByName(MatchAttribute)
    		If n.Value = FilterName Then
    			FindFilter = i
    		End If
        End If
    Next
End Function

