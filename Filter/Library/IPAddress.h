/*
    AQTRONIX C++ Library
    Copyright 2003-2013 Parcifal Aertssen

    This file is part of AQTRONIX C++ Library.

    AQTRONIX C++ Library is free software; you can redistribute it
	and/or modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2 of
	the License, or (at your option) any later version.

    AQTRONIX C++ Library is distributed in the hope that it will be
	useful, but WITHOUT ANY WARRANTY; without even the implied warranty
    of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with AQTRONIX C++ Library; if not, write to the Free
    Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
    MA  02111-1307  USA
*/
// IPAddress.h: interface for the CIPAddress class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_IPADDRESS_H__8D511D6D_CBC9_4BB9_946C_B1214FF12741__INCLUDED_)
#define AFX_IPADDRESS_H__8D511D6D_CBC9_4BB9_946C_B1214FF12741__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "IPAddressTemplate.h"

//implementations
typedef CIPAddressTemplate<IPV4_SIZE> CIP4Address;
typedef CIPAddressTemplate<IPV6_SIZE> CIP6Address;
typedef CIP4Address CIPAddress;	//deprecated - backwards compatibility


#endif // !defined(AFX_IPADDRESS_H__8D511D6D_CBC9_4BB9_946C_B1214FF12741__INCLUDED_)
