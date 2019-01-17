/*
    AQTRONIX C++ Library
    Copyright 2016 Parcifal Aertssen

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
#include "StdAfx.h"
#include "Action.h"

Action::Action(void)
{
	SetAll(false);
}

Action::Action(const Action& a)
{
	for(int i=0;i<MAX_ACTIONS;i++){
		Status[i] = a.Status[i];
	}
}

Action::~Action(void)
{
}

void Action::Set(int i)
{
	if(i<0){
		SetAll(false);
	}else if(i<MAX_ACTIONS){
		Status[i] = true;
	}else{
		SetAll(true);
	}
}

void Action::Set(bool b)
{
	Status[Block] = b;
}

void Action::SetAll(bool b)
{
	for(int i=0;i<MAX_ACTIONS;i++){
		Status[i] = b;
	}
}

Action& Action::operator |=(const bool b)
{
	Status[Block] |= b;
	return *this;
}

Action& Action::operator |=(const Action& a)
{
	for(int i=0;i<MAX_ACTIONS;i++){
		Status[i] |= a.Status[i];
	}
	return *this;
}

bool Action::IsEmpty()
{
	for(int i=0;i<MAX_ACTIONS;i++){
		if(Status[i]==true){
			return false;
		}
	}
	return true;
}

