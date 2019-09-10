#include <stdio.h>
#include <Windows.h>
#include <WinNT.h>
#ifndef __HASH_READ_H__
#define __HASH_READ_H__

DWORD ReadDWORD(BYTE * fr,int *cur);
WORD ReadWORD(BYTE * fr ,int *cur);
void ReadString(BYTE * fr,int *cur);


#endif