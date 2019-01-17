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

#if !defined(AFX_IPADDRESSTEMPLATE_H__8D511D6D_CBC9_4BB9_946C_B1214FF12741__INCLUDED_)
#define AFX_IPADDRESSTEMPLATE_H__8D511D6D_CBC9_4BB9_946C_B1214FF12741__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "StringHelper.h"

/* Changelog
 * 2016.03.17 BUGFIX: IsIPAddress verifies <Size> addresses only (CIP6Address also accepted IPv4 addresses)
 * 2013.04.14 FEAT: Ready for parsing IPv6 notation: Changed IsIPAddress/SetIP
 *				    Added ToIPvXString(),IsIPAddressDoubleHexa(),Expand()
 * 2012.10.02 BUGFIX: SetIP("1.1.1.1.") resulted in stack corruption
 * 2008.09.23 Moved XOR,OR,AND from CIPRange to this class
 * 2008.09.22 Changed this class to template for IPv6 (CIPAddress -> CIPAddressTemplate)
 * 2006.03.20 Added ToHexString() and ToStringTriplets
 * 2006.02.18 Added IsIPAddress (IPv4+IPv6 ready)
 * 2006.02.05 Added Reverse() for DNS blacklist lookups
 * 2005.10.25 Conversion int -> unsigned char for performance
 *			  moved Safe_atoi to CStringHelper class and use new
 *            function Safe_AsciiToUChar
 * 2005.10.02 Added SetIP(LPCTSTR) and CIPAddress(LPCTSTR)
 *            Moved ConvertCIDRToSubnet() from class CIPRange to here
 * 2005.07.06 Added SetAllValues() and operator = and CIPAddress(CIPAddress&)
 * 2004.01.16 First version of class finished
 * 2003.10.15 Created class for MailKnight
 */

#define IPV4_SIZE  4	//IPv4 == 32bit
#define IPV6_SIZE 16	//IPv6 == 128bit

//interface
class IIPAddress: public CObject{
public:
	virtual unsigned char GetSize() = 0;
	virtual CString ToString() const = 0;
};

//template
template <unsigned char Size>
class CIPAddressTemplate: public IIPAddress
{
public:
	unsigned char GetSize(){ return Size; };
	static bool IsIPAddress(CString& IP);
	static bool IsIPAddressQuad(CString& byte);
	static bool IsIPAddressDoubleHexa(CString& byte);
	CIPAddressTemplate Reverse();
	static CIPAddressTemplate ConvertCIDRToSubnet(unsigned char Subnet);
	void SetMin();
	void SetMax();
	
	static CString Expand(CString IP);
	CString ToIPv6String() const;
	CString ToIPv4String() const;
	CString ToHexString() const;
	CString ToStringTriplets() const;
	virtual CString ToString() const;
	bool operator != (const CIPAddressTemplate& IP) const;
	bool operator == (const CIPAddressTemplate& IP) const;
	bool operator < (const CIPAddressTemplate& IP) const;
	bool operator > (const CIPAddressTemplate& IP) const;
	CIPAddressTemplate& operator = (const CIPAddressTemplate& IP);
	CIPAddressTemplate OR(CIPAddressTemplate& IPFactor);
	CIPAddressTemplate AND(CIPAddressTemplate& IPFactor);
	CIPAddressTemplate XOR(CIPAddressTemplate& IPFactor);
	
	bool SetIP(const CIPAddressTemplate& IP);
	bool SetIP(CString IP);
	bool SetIP(LPCTSTR IP);
	
	CIPAddressTemplate(LPCTSTR IP);
	CIPAddressTemplate(CString IP);
	CIPAddressTemplate(const CIPAddressTemplate& IP);
	CIPAddressTemplate();
	virtual ~CIPAddressTemplate();

	unsigned char m_IP[Size];

protected:
	inline void SetAllValues(unsigned char Value);
};

template <unsigned char Size> CIPAddressTemplate<Size>::CIPAddressTemplate()
{
	SetAllValues(0);	//defaults
}

template <unsigned char Size> CIPAddressTemplate<Size>::CIPAddressTemplate(CString IP)
{
	SetAllValues(0);	//defaults
	//Set IP address
	if(IP!="")
		SetIP(IP);
}

template <unsigned char Size> CIPAddressTemplate<Size>::CIPAddressTemplate(LPCTSTR IP)
{
	SetAllValues(0);	//defaults
	if(IP!=NULL)
		SetIP(IP);
}

template <unsigned char Size> CIPAddressTemplate<Size>::CIPAddressTemplate(const CIPAddressTemplate& IP)
{
	SetIP(IP);
}

template <unsigned char Size> CIPAddressTemplate<Size>::~CIPAddressTemplate()
{

}

template <unsigned char Size> bool CIPAddressTemplate<Size>::SetIP(LPCTSTR IP)
{
	return SetIP(CString(IP));
}

template <unsigned char Size> bool CIPAddressTemplate<Size>::SetIP(CString IP)
{
	SetAllValues(0);
	CString byte("");
	unsigned char quadcounter = 0;

	//IPv6 - expand ::
	IP = Expand(IP);

	bool ishybrid = true;	//::ffff:192.168.89.9
	for(int i=0;i<IP.GetLength();i++){
		if(IP[i] == ':' && quadcounter<Size-3){
			//IPv6
			if(byte=="" || byte=="0"){
				m_IP[quadcounter] = 0;
				m_IP[quadcounter+1] = 0;
			}else{
				if(byte.GetLength()<4){
					//add leading zero's
					byte = CString('0',4-byte.GetLength()) + byte;
				}
				m_IP[quadcounter] = CStringHelper::Safe_HexToUChar(byte.Left(2));
				m_IP[quadcounter+1] = CStringHelper::Safe_HexToUChar(byte.Right(2));
			}
			byte = "";
			quadcounter +=2;
			ishybrid = false;
		}else if(IP[i] == '.' && quadcounter<Size-1){
			//IPv4
			m_IP[quadcounter] = CStringHelper::Safe_AsciiToUChar(byte);
			byte = "";
			quadcounter++;
			ishybrid = true;
		}else{
			byte += IP[i];
		}
	}
	if(ishybrid){
		m_IP[quadcounter] = CStringHelper::Safe_AsciiToUChar(byte);
	}else{
		if(byte.GetLength()<4){
			//add leading zero's
			byte = CString('0',4-byte.GetLength()) + byte;
		}
		m_IP[quadcounter] = CStringHelper::Safe_HexToUChar(byte.Left(2));
		m_IP[quadcounter+1] = CStringHelper::Safe_HexToUChar(byte.Right(2));
	}
	return true;
}

template <unsigned char Size> bool CIPAddressTemplate<Size>::SetIP(const CIPAddressTemplate& IP)
{
	for(unsigned char i=0;i<Size;i++){
		m_IP[i] = IP.m_IP[i];
	}
	return true;
}

template <unsigned char Size> CString CIPAddressTemplate<Size>::Expand(CString IP)
{
	//IPv6 - Expand "::" if less than required for full address notation
	int pos = IP.Find(_T("::"));
	if(pos>-1){
		int c = 0;
		bool ishybrid = false;
		for(int i=0;i<IP.GetLength();i++){
			if(IP[i]==':' && c<Size-3){
				c += 2;
				ishybrid = false;
			}else if(IP[i]=='.' && c<Size-1){
				c++;
				ishybrid = true;
			}
		}
		if(IP.Right(1)!=':'){
			if(ishybrid){
				c++;
			}else{
				c+=2;
			}
		}
		if(c<Size){
			//::1 -> :::::::1
			IP.Insert(pos,CString(':',((Size-c)/2)));
		}
	}
	return IP;
}

template <unsigned char Size> CIPAddressTemplate<Size>& CIPAddressTemplate<Size>::operator = (const CIPAddressTemplate& IP)
{
	SetIP(IP);
	return *this;
}

template <unsigned char Size> bool CIPAddressTemplate<Size>::operator > (const CIPAddressTemplate& IP) const
{
	for(unsigned char i=0;i<Size;i++){
		if(m_IP[i]>IP.m_IP[i]){
			return true;
		}else{
			if(m_IP[i]<IP.m_IP[i])
				return false;
		}
	}
	return false;	//they are equal!
}

template <unsigned char Size> bool CIPAddressTemplate<Size>::operator < (const CIPAddressTemplate& IP) const
{
	for(unsigned char i=0;i<Size;i++){
		if(m_IP[i]<IP.m_IP[i]){
			return true;
		}else{
			if(m_IP[i]>IP.m_IP[i])
				return false;
		}
	}
	return false;	//the're equal
}

template <unsigned char Size> bool CIPAddressTemplate<Size>::operator == (const CIPAddressTemplate& IP) const
{
	for(unsigned char i=0;i<Size;i++){
		if(m_IP[i]!=IP.m_IP[i]){
			return false;
		}
	}
	return true;
}

template <unsigned char Size> bool CIPAddressTemplate<Size>::operator != (const CIPAddressTemplate& IP) const
{
	return !(this->operator==(IP));
}

template <unsigned char Size> CIPAddressTemplate<Size> CIPAddressTemplate<Size>::XOR(CIPAddressTemplate &IPFactor)
{
	CIPAddressTemplate<Size> IPResult;
	for(unsigned char i=0;i<Size;i++){
		IPResult.m_IP[i] = m_IP[i]^IPFactor.m_IP[i];
	}
	return IPResult;
}

template <unsigned char Size> CIPAddressTemplate<Size> CIPAddressTemplate<Size>::AND(CIPAddressTemplate &IPFactor)
{
	CIPAddressTemplate<Size> IPResult;
	for(unsigned char i=0;i<Size;i++){
		IPResult.m_IP[i] = m_IP[i]&IPFactor.m_IP[i];
	}
	return IPResult;
}

template <unsigned char Size> CIPAddressTemplate<Size> CIPAddressTemplate<Size>::OR(CIPAddressTemplate &IPFactor)
{
	CIPAddressTemplate<Size> IPResult;
	for(unsigned char i=0;i<Size;i++){
		IPResult.m_IP[i] = m_IP[i]|IPFactor.m_IP[i];
	}
	return IPResult;
}

template <unsigned char Size> CString CIPAddressTemplate<Size>::ToString() const
{
	if(Size>4){
		return ToIPv6String();
	}else{
		return ToIPv4String();
	}
}

template <unsigned char Size> CString CIPAddressTemplate<Size>::ToIPv4String() const
{
	//123.123.123.123
	CString IP("");
	char buf[34] = "\0";
	for(unsigned char i=0;i<Size;i++){
		IP += _itoa(m_IP[i],buf,10);
		if(i<Size-1)
			IP+=".";
	}
	return IP;
}

template <unsigned char Size> CString CIPAddressTemplate<Size>::ToIPv6String() const
{
	//1122:3344:AABB:CCDD
	CString IP("");
	char buf[34] = "\0";
	for(unsigned char i=0;i<Size;i++){
		if(m_IP[i]<16){
			IP += "0";
		}
		IP += _itoa(m_IP[i],buf,16);
		if(i%2==1 && i<Size-2)
			IP+=":";
	}
	IP.MakeLower();
	return IP;
}

template <unsigned char Size> CString CIPAddressTemplate<Size>::ToStringTriplets() const
{
	CString IP("");
	CString item;
	char buf[34] = "\0";
	for(unsigned char i=0;i<Size;i++){
		item = _itoa(m_IP[i],buf,10);
		switch(item.GetLength()){
		case 1:
			IP += "00";
			break;
		case 2:
			IP += "0";
			break;
		}
		IP+=item;
	}
	return IP;
}

template <unsigned char Size> CString CIPAddressTemplate<Size>::ToHexString() const
{
	CString IP("");
	char buf[34] = "\0";
	for(unsigned char i=0;i<Size;i++){
		if(m_IP[i]<16){
			IP += "0";
		}
		IP += _itoa(m_IP[i],buf,16);
	}
	IP.MakeUpper();
	return IP;
}

template <unsigned char Size> void CIPAddressTemplate<Size>::SetMax()
{
	//set max;
	SetAllValues(255);
}

template <unsigned char Size> void CIPAddressTemplate<Size>::SetMin()
{
	//set min
	SetAllValues(0);
}

template <unsigned char Size> inline void CIPAddressTemplate<Size>::SetAllValues(unsigned char Value)
{
	//Set all values
	for(unsigned char ic=0;ic<Size;ic++){
		m_IP[ic] = Value;
	}
}

template <unsigned char Size> CIPAddressTemplate<Size> CIPAddressTemplate<Size>::ConvertCIDRToSubnet(unsigned char Subnet)
{
	CIPAddressTemplate<Size> SubnetMask;
	if(Subnet>Size*8){
		SubnetMask.SetMax();
	}else{
		unsigned char i=0;
		while(Subnet>7){
			SubnetMask.m_IP[i] = 255;
			i++;
			Subnet -=8;
		}
		unsigned char chunk = 128;
		SubnetMask.m_IP[i] = 0;
		while(Subnet>0){
			SubnetMask.m_IP[i] += chunk;
			chunk /=2;
			Subnet--;
		}
	}
	return SubnetMask;
}

template <unsigned char Size> CIPAddressTemplate<Size> CIPAddressTemplate<Size>::Reverse()
{
	//reverse ip
	CIPAddressTemplate<Size> rev;
	for(unsigned char ic=0;ic<Size;ic++){
		rev.m_IP[Size-1-ic] = m_IP[ic];
	}
	return rev;
}

template <unsigned char Size> bool CIPAddressTemplate<Size>::IsIPAddress(CString &IP)
{
	CString byte("");
	unsigned char quadcounter = 0;

	//IPv6 - Expand ::
	IP = Expand(IP);

	bool ishybrid = true;
	for(int i=0;i<IP.GetLength();i++){
		if(IP[i] == ':' && quadcounter<Size-3){
			//IPv6
			if(byte!="" && !IsIPAddressDoubleHexa(byte)){
				return false;
			}
			byte = "";
			quadcounter+=2;
			ishybrid = false;
		}else if(IP[i] == '.' && quadcounter<Size-1){
			//IPv4
			if(!IsIPAddressQuad(byte)){
				return false;
			}
			byte = "";
			quadcounter++;
			ishybrid = true;
		}else{
			byte += IP[i];
		}
	}

	if(ishybrid){
		if(IsIPAddressQuad(byte)){
			quadcounter++;
		}else{
			return false;
		}
	}else{
		if(IsIPAddressDoubleHexa(byte)){
			quadcounter += 2;
		}
	}
	
	return (quadcounter==Size);
}

template <unsigned char Size> bool CIPAddressTemplate<Size>::IsIPAddressQuad(CString &byte)
{
	if(byte.GetLength()>0){
		int ipseq = CStringHelper::Safe_AsciiToInt(byte,-1);
		return (ipseq > -1 && ipseq<256);
	}
	return false;
}

template <unsigned char Size> bool CIPAddressTemplate<Size>::IsIPAddressDoubleHexa(CString &byte)
{
	if(byte.GetLength()>0 && byte.GetLength()<5){
		int ipseq = CStringHelper::Safe_HexToInt(byte,-1);
		return (ipseq > -1 && ipseq<65537);
	}
	return false;
}

#endif // !defined(AFX_IPADDRESSTEMPLATE_H__8D511D6D_CBC9_4BB9_946C_B1214FF12741__INCLUDED_)
