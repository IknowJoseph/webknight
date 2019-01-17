Const ForReading = 1
Const ForWriting = 2
Const FileIn = "WebKnight.xml"
Const FileOut = "WebKnight.xml"  '<== Change to prevent overwrite of original file

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.OpenTextFile(FileIn, ForReading)

strText = objFile.ReadAll
objFile.Close

'add wizard texts
strText = Replace(strText, "<AQTRONIX_WebKnight_Configuration App='Title'/>", "<AQTRONIX_WebKnight_Configuration App='Title' Wizard='This configuration file has a wizard to get you started with WebKnight. Click Next to begin.'/>")
strText = Replace(strText, "<Response_Log_Only App='Option' Default='0' Explanation='If an attack is detected, only log and do not block it. If you want the firewall to go completely stealth, also disable the &apos;Response Headers&apos; in &apos;Response Monitor&apos;.'>", "<Response_Log_Only App='Option' Default='0' Explanation='If an attack is detected, only log and do not block it. If you want the firewall to go completely stealth, also disable the &apos;Response Headers&apos; in &apos;Response Monitor&apos;.' Wizard='When starting with WebKnight it is recommended to run it in Log Only mode. Monitor the WebKnight log files and once you have configured WebKnight and reduced the false positives, you can disable the Response Log Only setting again.'>")
strText = Replace(strText, "<Connection_Client_IP_Variable App='Text' Default='' Explanation='The server variable to get the client IP address. Use this when the incoming requests are coming from a CDN/reverse proxy. Examples are: HTTP_X_FORWARDED_FOR or HTTP_TRUE_CLIENT_IP. If empty, REMOTE_ADDR is used.'>", "<Connection_Client_IP_Variable App='Text' Default='' Explanation='The server variable to get the client IP address. Use this when the incoming requests are coming from a CDN/reverse proxy. Examples are: HTTP_X_FORWARDED_FOR or HTTP_TRUE_CLIENT_IP. If empty, REMOTE_ADDR is used.' Wizard='Are you running your IIS machine behind a CDN or reverse proxy? Specify what server variable WebKnight should use to get the real client IP address. When in doubt, skip this.'>")
strText = Replace(strText, "<Scan_Forms_Authentication App='Option' Default='1' Explanation='Scan Forms Authentication attempts. The username and password are extracted using the input field name lists. Excluded Web Instances are always ignored.'>", "<Scan_Forms_Authentication App='Option' Default='1' Explanation='Scan Forms Authentication attempts. The username and password are extracted using the input field name lists. Excluded Web Instances are always ignored.' Wizard='WebKnight can protect your logon page from brute force authentication attempts. All you need to do is add the form field names for the username and password.'>")
strText = Replace(strText, "<Denied_Url_Sequences App='Select' Default='1' Explanation='' Display='Disabled;Block;Monitor;Block IP;Monitor IP'>", "<Denied_Url_Sequences App='Select' Default='1' Explanation='' Display='Disabled;Block;Monitor;Block IP;Monitor IP' Wizard='Certain urls are blocked by default like /admin or /phpmyadmin as they are being probed by botnets and other scanners for vulnerabilities. When you need public access to these urls, remove them from the Denied Url Sequences otherwise add the IP addresses that need access to the Excluded IP addresses in the Connection section.'>")
strText = Replace(strText, "<Allowed_Paths App='Select' Default='1' Explanation='' Display='Disabled;Block;Monitor;Block IP;Monitor IP'>", "<Allowed_Paths App='Select' Default='1' Explanation='' Display='Disabled;Block;Monitor;Block IP;Monitor IP' Wizard='Are you running websites outside &quot;C:\InetPub\wwwroot&quot;? Add the folders in Allowed Paths.'>")
strText = Replace(strText, "<Web_Applications App='Separator'/>", "<Web_Applications App='Separator' Wizard='What web applications are you running? Enable the required functionality in the section Web Applications. When you have non US-ASCII characters in the filenames of your webpages, allow Unicode.'/>")

'show navigation bar
'strText = Replace(strText, "<WebKnight_Configuration App='Document'/>", "<WebKnight_Configuration App='Document' NavigationBar='1'/>")

Set objFile = objFSO.OpenTextFile(FileOut, ForWriting)
objFile.WriteLine strText
objFile.Close