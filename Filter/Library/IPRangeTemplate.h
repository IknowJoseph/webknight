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
// CIPRangeTemplate.h: implementation of the CIPRangeTemplate class.
//
//////////////////////////////////////////////////////////////////////

#include "math.h"

/* Changelog
 * 2013.04.15 Changed class to template for IPv4 & IPv6 ranges
 * 2008.09.23 Moved XOR,AND,OR to CIPAddressTemplate (for IPv6)
 * 2008.09.22 Added ':' to allowed range characters (for IPv6)
 * 2008.01.21 Fixed bug missing allowed character '-' in IsValidIPRange()
 * 2007.05.04 Added GetSubnetID()
 * 2005.10.25 Did some int -> unsigned char conversions for performance
 * 2005.10.02 Changed CString parameter of IsInRange() to LPCTSTR
 *            Moved ConvertCIDRToSubnet() to class CIPAddress
 * 2005.08.03 Added range format 10.0.0.1-10.0.0.2
 * 2005.07.05 Code review + use assignment operator of CIPAddress class (=)
 * 2004.01.16 First version of class finished
 * 2003.10.15 Created class for MailKnight
 */

//interface
class IIPRange: public CObject
{
public:
	virtual unsigned char GetSize() = 0;
	virtual bool SetIPRange(CString IPRange) = 0;
	virtual CString ToString() const = 0;
};

//template
template <unsigned char Size>
class CIPRangeTemplate: public IIPRange 
{

protected:
	CIPAddressTemplate<Size> StartIP;
	CIPAddressTemplate<Size> EndIP;
	CIPAddressTemplate<Size> SubnetMask;
	CIPAddressTemplate<Size> Max;

public:
	unsigned char GetSize(){ return Size;};
	bool IsInRange(LPCTSTR IP);
	bool IsInRange(CIPAddressTemplate<Size>& IP);

	bool SetIPRange(CString IPRange);
	bool SetIPRange(CIPAddressTemplate<Size>& StartIP, CIPAddressTemplate<Size>& EndIP);
	static bool IsValidIPRange(CString &IP);
	static CString GetSubnetID(CString& IP, CString& CIDR);

	CString GetEndIP() const;
	CString GetStartIP() const;
	CString GetSubnetMask() const;
	CString ToString() const;

	CIPRangeTemplate(CString IPRange);
	CIPRangeTemplate(CIPAddressTemplate<Size>& StartIP, CIPAddressTemplate<Size>& EndIP);
	CIPRangeTemplate();
	virtual ~CIPRangeTemplate();

};

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

template <unsigned char Size> CIPRangeTemplate<Size>::CIPRangeTemplate()
{
	Max.SetMax();
}

template <unsigned char Size> CIPRangeTemplate<Size>::CIPRangeTemplate(CIPAddressTemplate<Size>& StartIP, CIPAddressTemplate<Size>& EndIP)
{
	Max.SetMax();
	SetIPRange(StartIP,EndIP);
}

template <unsigned char Size> CIPRangeTemplate<Size>::CIPRangeTemplate(CString IPRange)
{
	Max.SetMax();
	SetIPRange(IPRange);
}

template <unsigned char Size> CIPRangeTemplate<Size>::~CIPRangeTemplate()
{

}

template <unsigned char Size> CString CIPRangeTemplate<Size>::GetStartIP() const
{
	return StartIP.ToString();
}

template <unsigned char Size> CString CIPRangeTemplate<Size>::GetEndIP() const
{
	return EndIP.ToString();
}

template <unsigned char Size> CString CIPRangeTemplate<Size>::GetSubnetMask() const
{
	return SubnetMask.ToString();
}

template <unsigned char Size> CString CIPRangeTemplate<Size>::GetSubnetID(CString& IP, CString& CIDR)
{
	CIPRangeTemplate<Size> range(IP + "/" + CIDR);
	return range.GetStartIP() + "/" + CIDR;
}

template <unsigned char Size> bool CIPRangeTemplate<Size>::IsValidIPRange(CString &IP)
{
	/*
	 * returns true if it contains only numbers, dots and '*' or '/' and cannot be empty (IPv4)
	 * IPv6: also allow colon + hex
	 */
	if(IP.GetLength()>0){
		for(int i=0;i<IP.GetLength();i++){
			if(IP[i] != '.' && ( IP[i]<48 || (IP[i]>57 && !((IP[i]>64 && IP[i]<71) || (IP[i]>96 && IP[i]<103)) ) ) && IP[i]!='*' && IP[i]!='/' && IP[i]!='-' && IP[i]!=':'){
				return false;
			}
		}
	}else{
		return false;
	}
	return true;
}

template <unsigned char Size> bool CIPRangeTemplate<Size>::IsInRange(CIPAddressTemplate<Size>& IP)
{
	if(IP<StartIP || IP>EndIP){
		return false;
	}else{
		return true;
	}
}

template <unsigned char Size> bool CIPRangeTemplate<Size>::IsInRange(LPCTSTR IP)
{
	CIPAddressTemplate<Size> IPa;
	if(IPa.SetIP(IP)){
		return IsInRange(IPa);
	}else{
		return false;
	}
}

template <unsigned char Size> bool CIPRangeTemplate<Size>::SetIPRange(CIPAddressTemplate<Size> &StartIP, CIPAddressTemplate<Size> &EndIP)
{
	//set start en end IP
	CIPRangeTemplate::StartIP = StartIP;
	CIPRangeTemplate::EndIP = EndIP;

	//set subnetmask
	CIPAddressTemplate<Size> SubnetID;
	SubnetID = StartIP.XOR(EndIP);
	SubnetMask = SubnetID.XOR(Max);

	return true;
}

template <unsigned char Size> bool CIPRangeTemplate<Size>::SetIPRange(CString IPRange)
{
	int possep;

	//remove everything after space (comments...)
	possep = IPRange.FindOneOf(_T(" \t"));
	if(possep>-1){
		IPRange = IPRange.Left(possep);
	}

	//is valid ip range?
	if(IsValidIPRange(IPRange)){
		possep = IPRange.Find('/');
		if(possep==-1){
			possep = IPRange.Find('-');
			if(possep==-1){
				//format 10.*.*.*
				while(IPRange.Find(_T("**"))!=-1){
					IPRange.Replace(_T("**"),_T("*"));
				}
				//startip
				CString RangeStart(IPRange);
				RangeStart.Replace(_T("*"),_T("0"));
				StartIP = RangeStart;
				//endip
				IPRange.Replace(_T("*"),_T("255"));
				EndIP = IPRange;
			}else{
				//format 10.0.0.1-10.0.0.2
				//startip
				StartIP = IPRange.Left(possep);
				//endip
				if(IPRange.GetLength()>possep){
					EndIP = IPRange.Mid(possep+1);
				}else{
					EndIP = StartIP;
				}
			}
			//subnetmask
			CIPAddressTemplate<Size> SubnetID;
			SubnetID = StartIP.XOR(EndIP);
			SubnetMask = SubnetID.XOR(Max);
		}else{
			//format 10.0.0.0/8
			unsigned char subnet;
			CString strSubnet = IPRange.Mid( (possep+1<IPRange.GetLength())?possep+1:possep );
			subnet = CStringHelper::Safe_AsciiToUChar(strSubnet);
			SubnetMask.SetIP(CIPAddressTemplate<Size>::ConvertCIDRToSubnet(subnet));
			//startip
			CIPAddressTemplate<Size> IP(IPRange.Left((possep>0?possep:possep-1)));
			StartIP = IP.AND(SubnetMask);
			//endip
			CIPAddressTemplate<Size> HostID;
			HostID = SubnetMask.XOR(Max);
			EndIP = StartIP.OR(HostID);
		}
		return true;
	}else{
		return false;
	}
}

template <unsigned char Size> CString CIPRangeTemplate<Size>::ToString() const
{
	return StartIP.ToString() + "-" + EndIP.ToString() ;
}
