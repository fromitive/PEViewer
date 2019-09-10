#include "HashRead.h"

//4byte를 읽고 현재 위치를 4byte 앞으로 이동시킴
DWORD ReadDWORD(BYTE * fr,int * cur)
{
	DWORD data = 0;
	int i;
	for(i=0;i<4;i++)
	{
		data+=fr[*cur+i]<<8*(i); //little endian 으로 저장 되어있는 것을  big endian으로 변환
	}
	*cur +=i;
	return data;
}

//2byte를 읽고 현재 위치를 2byte 앞으로 이동시킴
WORD ReadWORD(BYTE * fr ,int * cur)
{
	WORD data = 0;	
	int i;
	for(i=0;i<2;i++)
	{
		data+=fr[*cur+i]<<8*(i);
	}
	*cur +=i;
	return data;
}
//문자열을 읽고 현재 위치를 다음 데이터 ('\0' 이후로 위치 시킴)
void ReadString(BYTE * fr,int * cur)
{
	int i=0;
	while(1)
	{
		if(fr[*cur+i]=='\0')
			break;
		printf("%c",fr[*cur+i]);
		i++;

	}
	*cur +=i;
	return;
}