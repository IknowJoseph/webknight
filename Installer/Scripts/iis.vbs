'
'IIS.vbs
'Script for adding/removing WebKnight in IIS
'
Option Explicit

Dim HostName
Dim FilterName
Dim FilterPath
Dim FilterDesc
Dim Bitness
Dim Action
Dim par
Dim IISVersion

FilterName = "WebKnight"
FilterDesc = "Filter for securing IIS"
HostName = "LocalHost"				'uncomment this for unattended setup

FilterPath = Session.Property("WEBKNIGHTDIR")
Bitness = Session.Property("BITNESS")
Action = Session.Property("ACTION")
If FilterPath = "" Or Bitness = "" Or Action = "" Then
	par = Split(Session.Property("CustomActionData"),"|")
	Action = par(0)
	Bitness = par(1)
	FilterPath = par(2)
End If

IISVersion = GetIISVersion()

'add trailing slash if not there
If Right(FilterPath,1)<>"\" And Right(FilterPath,1)<>"/" Then
	FilterPath = FilterPath & "\"
End If

Select Case Action
	Case "Install"
		RegisterIISFilter FilterName,HostName,FilterPath
	Case "Uninstall"
		UnRegisterIISFilter FilterName, HostName
	Case "Upgrade"
		'installing ISAPI Extension in IIS 7 when upgrading from 1.x/2.x to 3.x
		UpgradeIISFilter FilterName,FilterPath
End Select


'-----------------------------------------------------------------
'                             Upgrade
'-----------------------------------------------------------------

Sub UpgradeIISFilter(FilterName,FilterPath)	
	If IsIIS7OrLater() Then
		'only if upgrading from 1.x and 2.x
		If UpgradeIIS7Filter(FilterName,Bitness) Then
			On Error Resume Next
			RegisterIIS7Extension FilterName,FilterPath,Bitness,FilterName & ".dll" 'new in 3.x
			If Bitness=64 Then 'for 32 bit app pools (also missing in 2.x setup)
				RegisterIIS7Filter FilterName,FilterPath,"32",FilterName & ".32bit.dll"
				RegisterIIS7Extension FilterName,FilterPath,"32",FilterName & ".32bit.dll"
			End If
			SetNTFSPermission FilterPath, "IUSR","C" 'needed for admin /WebKnight/default.asp
		End If
	End If
End Sub

Function UpgradeIIS7Filter(FilterName,Bitness)
    'set bitness precondition (missing in 2.x setup)

    Dim AdminManager
    Dim IsapiFiltersSection
    Dim IsapiFiltersCollection
	Dim FilterElement
    Dim ElementPos
	UpgradeIIS7Filter = False
	
    Set AdminManager = CreateObject("Microsoft.ApplicationHost.WritableAdminManager")
    AdminManager.CommitPath = "MACHINE/WEBROOT/APPHOST"

	'filter
    Set IsapiFiltersSection = AdminManager.GetAdminSection("system.webServer/isapiFilters", "MACHINE/WEBROOT/APPHOST")
    Set IsapiFiltersCollection = IsapiFiltersSection.Collection
    ElementPos = FindFilter(IsapiFiltersCollection,FilterName,"filter","name")
    If ElementPos>-1 Then
		UpgradeIIS7Filter = True
		Set FilterElement = IsapiFiltersCollection.Item(ElementPos)
		FilterElement.Properties.Item("name").Value = FilterName & " " & Bitness & "-bit"
		FilterElement.Properties.Item("preCondition").Value = "bitness" & Bitness
    End If
	
    AdminManager.CommitChanges()
	
	Set FilterElement = Nothing
    Set IsapiFiltersCollection = Nothing
    Set IsapiFiltersSection = Nothing	
    Set AdminManager = Nothing
End Function

'-----------------------------------------------------------------
'                           IIS Install
'-----------------------------------------------------------------

Sub RegisterIISFilter(FilterName,HostName,FilterPath)
	'Install
	If IsIIS7OrLater() Then
		RegisterIIS7Filter FilterName,FilterPath,Bitness,FilterName & ".dll"
		RegisterIIS7Extension FilterName,FilterPath,Bitness,FilterName & ".dll"
		If Bitness=64 Then 'for 32 bit app pools
			RegisterIIS7Filter FilterName,FilterPath,"32",FilterName & ".32bit.dll"
			RegisterIIS7Extension FilterName,FilterPath,"32",FilterName & ".32bit.dll"
		End If
		'notify user
		'MsgBox FilterName & " is succesfully installed." & vbCRLF & vbCRLF & "You should review the settings of " & FilterName & " (by running config.exe in " & FilterPath & ").",,FilterName
	Else
	    RegisterIISFilterMetabase FilterName,HostName,FilterPath,FilterName & ".dll"
	End If
End Sub

Sub RegisterIISFilterMetabase(FilterName,HostName,FilterPath,FilterDLLName)
    'Install as IIS 5 & 6 Filter
    Dim Filters
    Dim Filter
    Dim LoadOrder

    If Left(FilterPath,1)="\" Then	'no UNC paths!
	    MsgBox "UNC paths not allowed!",,FilterName
    Else
	    'get list of filters on the host
	    Set Filters = GetObject("IIS://" & HostName & "/W3SVC/Filters")
	    LoadOrder = Filters.FilterLoadOrder

	    If InStr(1,LoadOrder,FilterName)>0 Then	'filter already installed?
		    MsgBox FilterName & " is already installed on " & HostName,,FilterName
	    Else
		    'register filter in IIS metabase
		    'set filter to be loaded first (high security)
		    If LoadOrder <> "" Then
			    LoadOrder = "," & LoadOrder
		    End If
		    LoadOrder = FilterName & LoadOrder
		    If InStr(1,LoadOrder,"Compression")>0 Then
			    LoadOrder = Replace(LoadOrder,"Compression","")
			    LoadOrder = Replace(LoadOrder,",,",",")
			    LoadOrder = "Compression," & LoadOrder
		    End If
		    If InStr(1,LoadOrder,"sspifilt")>0 Then
			    LoadOrder = Replace(LoadOrder,"sspifilt","")
			    LoadOrder = Replace(LoadOrder,",,",",")
			    LoadOrder = "sspifilt," & LoadOrder
		    End If
		    Filters.FilterLoadOrder = LoadOrder
		    Filters.SetInfo

		    'make filter
		    Set Filter = Filters.Create("IIsFilter", FilterName)
		    Filter.FilterPath = FilterPath & FilterDLLName
		    Filter.FilterDescription = FilterDesc
		    Filter.SetInfo

		    'notify user
		    'MsgBox FilterName & " is succesfully installed." & vbCRLF & vbCRLF & "You should review the settings of " & FilterName & " (by running config.exe in " & FilterPath & ").",,FilterName
	    End If
    End If
End Sub

Sub RegisterIIS7Filter(FilterName,FilterPath,Bitness,FilterDLLName)
    'install ISAPI filter/extension using IIS7 API (filter is more important)

    Dim AdminManager
    Dim IsapiFiltersSection
    Dim IsapiFiltersCollection
    Dim FilterElement

    Set AdminManager = CreateObject("Microsoft.ApplicationHost.WritableAdminManager")
    AdminManager.CommitPath = "MACHINE/WEBROOT/APPHOST"

	'add ISAPI filter
    Set IsapiFiltersSection = AdminManager.GetAdminSection("system.webServer/isapiFilters", "MACHINE/WEBROOT/APPHOST")
    Set IsapiFiltersCollection = IsapiFiltersSection.Collection
    Set FilterElement = IsapiFiltersCollection.CreateNewElement("filter")
    FilterElement.Properties.Item("name").Value = FilterName & " " & Bitness & "-bit"
    FilterElement.Properties.Item("path").Value = FilterPath & FilterDLLName
	FilterElement.Properties.Item("preCondition").Value = "bitness" & Bitness
    IsapiFiltersCollection.AddElement(FilterElement)
	
    AdminManager.CommitChanges()
  
	'cleanup
	Set FilterElement = Nothing
    Set IsapiFiltersCollection = Nothing
    Set IsapiFiltersSection = Nothing
	Set AdminManager = Nothing

End Sub

Sub RegisterIIS7Extension(FilterName,FilterPath,Bitness,FilterDLLName)
    'install ISAPI extension using IIS7 API (new in WebKnight 3.0)
	On Error Resume Next 'gracefully complete installation

    Dim AdminManager
	Dim handlersSection
	Dim handlersCollection
	Dim isapiCgiRestrictionSection
	Dim isapiCgiRestrictionCollection
	Dim addElement

    Set AdminManager = CreateObject("Microsoft.ApplicationHost.WritableAdminManager")
    AdminManager.CommitPath = "MACHINE/WEBROOT/APPHOST"
	
	'add ISAPI extension
	Set handlersSection = AdminManager.GetAdminSection("system.webServer/handlers", "MACHINE/WEBROOT/APPHOST")
	Set handlersCollection = handlersSection.Collection
	Set addElement = handlersCollection.CreateNewElement("add")
	addElement.Properties.Item("name").Value = FilterName & " " & Bitness & "-bit"
	addElement.Properties.Item("path").Value = "*"
	addElement.Properties.Item("verb").Value = "*"
	addElement.Properties.Item("modules").Value = "IsapiModule"
	addElement.Properties.Item("scriptProcessor").Value = FilterPath & FilterDLLName
	addElement.Properties.Item("resourceType").Value = "Unspecified"
	addElement.Properties.Item("requireAccess").Value = "None"
	addElement.Properties.Item("preCondition").Value = "bitness" & Bitness
	handlersCollection.AddElement addElement, 0
	
	'allow ISAPI extension in CGI/ISAPI security
	Set isapiCgiRestrictionSection = AdminManager.GetAdminSection("system.webServer/security/isapiCgiRestriction", "MACHINE/WEBROOT/APPHOST")
	Set isapiCgiRestrictionCollection = isapiCgiRestrictionSection.Collection
	Set addElement = isapiCgiRestrictionCollection.CreateNewElement("add")
	addElement.Properties.Item("path").Value = FilterPath & FilterDLLName
	addElement.Properties.Item("allowed").Value = True
	addElement.Properties.Item("groupId").Value = FilterName
	addElement.Properties.Item("description").Value = FilterName & " " & Bitness & "-bit"
	isapiCgiRestrictionCollection.AddElement(addElement)
	
	AdminManager.CommitChanges()
  
	'cleanup
 	Set addElement = Nothing
	Set handlersCollection = Nothing
	Set handlersSection = Nothing
	Set isapiCgiRestrictionCollection = Nothing
	Set isapiCgiRestrictionSection = Nothing
	Set AdminManager = Nothing

End Sub

'-----------------------------------------------------------------
'                         IIS  Uninstall
'-----------------------------------------------------------------

Sub UnRegisterIISFilter(FilterName,HostName)
	'uninstall
	If IsIIS7OrLater() Then
	    UnRegisterIIS7Filter FilterName,FilterPath,Bitness,FilterName & ".dll"
		If Bitness=64 Then 'for 32 bit app pools
			UnRegisterIIS7Filter FilterName,FilterPath,"32",FilterName & ".32bit.dll"
		End If
	Else
	    UnRegisterIISFilterMetabase FilterName,HostName
	End If

End Sub

Sub UnRegisterIISFilterMetabase(FilterName,HostName)
    Dim Filters
    Dim Filter
    Dim LoadOrder

    'ask for hostname if we don't have one
    If HostName = "" Then
	    HostName = InputBox("Specify the IIS host from which you want to have " & FilterName & " uninstalled","Hostname required","LocalHost")
    End If
    
    If HostName <> "" Then 'user did not cancel?
    
	    'get list of installed filters
	    Set Filters = GetObject("IIS://" & HostName & "/W3SVC/Filters")
	    LoadOrder = Filters.FilterLoadOrder
	    If InStr(1,LoadOrder,FilterName)<1 Then
		    MsgBox "Filter is not installed on " & HostName,,FilterName
	    Else
    		
		    'remove filter from list
		    LoadOrder = Replace(LoadOrder,FilterName,"")
		    LoadOrder = Replace(LoadOrder,",,",",")
		    If Left(LoadOrder,1) = "," Then
			    LoadOrder = Mid(LoadOrder,2)
		    End If
		    If Right(LoadOrder,1) = "," Then
			    LoadOrder = Left(LoadOrder,Len(LoadOrder)-1)
		    End If
		    Filters.FilterLoadOrder = LoadOrder
		    Filters.SetInfo

		    'remove filter
		    Filters.Delete "IIsFilter",FilterName
		    
	    End If
    End If
End Sub

Sub UnRegisterIIS7Filter(FilterName,FilterPath,Bitness,FilterDLLName)
    'unregister ISAPI filter/extension using IIS7 API
	On Error Resume Next 'gracefully uninstall
    Dim AdminManager
    Dim IsapiFiltersSection
    Dim IsapiFiltersCollection
    Dim ElementPos
	
	Dim handlersSection
	Dim handlersCollection
	
	Dim isapiCgiRestrictionSection
	Dim isapiCgiRestrictionCollection

    Set AdminManager = CreateObject("Microsoft.ApplicationHost.WritableAdminManager")
    AdminManager.CommitPath = "MACHINE/WEBROOT/APPHOST"

	'filter
    Set IsapiFiltersSection = AdminManager.GetAdminSection("system.webServer/isapiFilters", "MACHINE/WEBROOT/APPHOST")
    Set IsapiFiltersCollection = IsapiFiltersSection.Collection
    ElementPos = FindFilter(IsapiFiltersCollection,FilterName & " " & Bitness & "-bit","filter","name")
    If ElementPos>-1 Then
        IsapiFiltersCollection.DeleteElement(ElementPos)
    End If
	
	'ISAPI extension
	Set handlersSection = AdminManager.GetAdminSection("system.webServer/handlers", "MACHINE/WEBROOT/APPHOST")
	Set handlersCollection = handlersSection.Collection
	ElementPos = FindFilter(handlersCollection,FilterName & " " & Bitness & "-bit","add","name")
	If ElementPos > -1 Then
		handlersCollection.DeleteElement(ElementPos)
	End If
	
	'ISAPI extension in CGI/ISAPI security exception
	Set isapiCgiRestrictionSection = AdminManager.GetAdminSection("system.webServer/security/isapiCgiRestriction", "MACHINE/WEBROOT/APPHOST")
	Set isapiCgiRestrictionCollection = isapiCgiRestrictionSection.Collection
	ElementPos = FindFilter(isapiCgiRestrictionCollection,FilterPath & FilterDLLName,"add","path")
    If ElementPos>-1 Then
        isapiCgiRestrictionCollection.DeleteElement(ElementPos)
    End If

	AdminManager.CommitChanges()
	
    Set IsapiFiltersCollection = Nothing
    Set IsapiFiltersSection = Nothing
	
	Set handlersCollection = Nothing
	Set handlersSection = Nothing
	
	Set isapiCgiRestrictionCollection = Nothing
	Set isapiCgiRestrictionSection = Nothing
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

'----------------------------------------------------------------
'                              NTFS
'-----------------------------------------------------------------

Sub SetNTFSPermission(Path,Username,Permission)
	'http://www.experts-exchange.com/Programming/Installation/InstallShield/Q_24315443.html
	If Right(Path,1) = "\" Then Path = Left(Path,Len(Path)-1)
	'MsgBox "cacls.exe """ & Path & """ /T /E /C /G """ & Username & """:" & Permission,,"Command"
	CreateObject("WScript.Shell").run "cacls.exe """ & Path & """ /T /E /C /G """ & Username & """:" & Permission
End Sub

'----------------------------------------------------------------
'                         IIS  Version
'-----------------------------------------------------------------

Function GetIISVersion
    'Get IIS Version
    Dim oShell
    Dim v:v = ""
    
    On Error Resume Next
    Set oShell = CreateObject("WScript.Shell")
    v = oShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\InetStp\MajorVersion")
    On Error Goto 0
    Set oShell = Nothing

    GetIISVersion = v
End Function

Function IsIIS7OrLater
	IsIIS7OrLater = False
	If IISVersion <> "" And IsNumeric(IISVersion) Then
		If IISVersion > 6 Then
			IsIIS7OrLater = True
		End If
	End If
End Function