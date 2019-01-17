
                          AQTRONIX WebKnight
                          ------------------                            

                ISAPI Filter for protecting web servers


Copyright
---------
AQTRONIX WebKnight - ISAPI Filter for securing Web Servers
Copyright 2002-2014 Parcifal Aertssen

This file is part of AQTRONIX WebKnight.

AQTRONIX WebKnight is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

AQTRONIX WebKnight is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with AQTRONIX WebKnight; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


A word of explanation on the source code:
-----------------------------------------
	CExploitScan
	     |
	CFirewall
	     | 
	CHTTPFirewall  	  CISAPIFilter
   		|	     |
		CISAPIFirewall
		      |
               CWebKnightFilter

These are the main filter classes that do all the work.
The most important functions are:
OnReadRawData: this is called by the web server when a request is received and
you can inspect the raw data here.
OnPreprocHeaders: is called when the headers are processed. Here you can
check the headers, url, method and version.
OnUrlMap is called whenever the web server needs to translate a url into a
physical path. Here you can check the url and the physical path.
OnSendRawData: this event is called whenever the web server sends something
back to the client. It's here we are changing or removing the server header.



	CSettings:
	    |
	CFirewallSettings
	    |
	CHTTPFirewallSettings
	    |
	CWebKnightSettings

These classes represent all settings/parameters that will be passed to the
filter. When an instance of this class is made, the default settings will
always be loaded first, even if you specify a settings file (e.g. "urlscan.ini").


All other classes are helper classes for the filter. You can read more
in the AQTRONIX library or source code itself.


Contact Information
-------------------
Website: http://www.aqtronix.com/
E-mail: parcifal@aqtronix.com

