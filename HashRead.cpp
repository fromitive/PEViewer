#include "HashRead.h"

//4byte�� �а� ���� ��ġ�� 4byte ������ �̵���Ŵ
DWORD ReadDWORD(BYTE * fr,int * cur)
{
	DWORD data = 0;
	int i;
	for(i=0;i<4;i++)
	{
		data+=fr[*cur+i]<<8*(i); //little endian ���� ���� �Ǿ��ִ� ����  big endian���� ��ȯ
	}
	*cur +=i;
	return data;
}

//2byte�� �а� ���� ��ġ�� 2byte ������ �̵���Ŵ
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
//���ڿ��� �а� ���� ��ġ�� ���� ������ ('\0' ���ķ� ��ġ ��Ŵ)
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