@echo off
:: batch file for updating the dll while programming
:: (only if you installed into the default dir)

:: stop web server
::iisreset /stop

:: copy new dll over old one
::copy /Y .\release\WebKnight.dll "C:\Program Files\AQTRONIX WebKnight\WebKnight.dll"
::copy /Y .\Debug\WebKnight.dll "C:\Program Files\AQTRONIX WebKnight\WebKnight.dll"
::copy /Y .\Debug\WebKnight.pdb "C:\Program Files\AQTRONIX WebKnight\WebKnight.pdb"

:: start the web server again
::iisreset /start

:: update Install dir
copy /Y .\release\WebKnight.dll ..\..\Setup\x64\WebKnight.dll

:: update readme
::copy /Y ..\..\Readme.htm ..\..\Setup\w32\Readme.htm
::copy /Y ..\..\Readme.htm ..\..\Setup\x64\Readme.htm

:: update library
::cd library
::call update.bat
