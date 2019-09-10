#include "HashRead.h"
DWORD RVAtoRAW(IMAGE_SECTION_HEADER * ArrOfSection,DWORD NumberOfSection,DWORD FA,DWORD FromRVA);

int main(void)
{
	FILE * fp;
	int end;
	int cur;
	BYTE * fileread;
	IMAGE_NT_HEADERS32 PE;
	const char * DataDirectoryName[][2] ={
{"RVA of EXPORT Directory","size of EXPORT Directory"},
{"RVA of IMPORT Directory","size of IMPORT Directory"},
{"RVA of RESOURCE Directory","size of RESOURCE Directory"},
{"RVA of EXCEPTION Directory","size of EXCEPTION Directory"},
{"RVA of SECURITY Directory","size of SECURITY Directory"},
{"RVA of BASERELOC Directory","size of BASERELOC Directory"},
{"RVA of DEBUG Directory","size of DEBUG Directory"},
{"RVA of COPYRIGHT Directory","size of COPYRIGHT Directory"},
{"RVA of GLOBALPTR Directory","size of GLOBALPTR Directory"},
{"RVA of TLS Directory","size of TLS Directory"},
{"RVA of LOAD_CONFIG Directory","size of LOAD_CONFIG Directory"},
{"RVA of BOUND_IMPORT Directory","size of BOUND_IMPORT Directory"},
{"RVA of IAT Directory","size of IAT Directory"},
{"RVA of DELAY_IMPOT Directory","size of of DELAY_IMPOT Directory"},
{"RVA of COM_DESCRIPTOR Directory","size of COM_DESCRIPTOR Directory"},
{"RVA of Reserved Directory","size of Reserved Directory"}};
	//1. 파일 읽어오기
	if((fp=fopen("kernel32.dll","rb"))==NULL)
	{
		printf("can't open \n");
		return -1;
	}
	else
	{
		fseek(fp,0,SEEK_END);
		end =ftell(fp);
		rewind(fp);
			//printf("%d ",end);
		fileread = (BYTE*)malloc(sizeof(BYTE)*end);
		fread(fileread ,sizeof(BYTE),end,fp);
		fclose(fp);
	}
	//파일 읽어오기 종료

	cur=0x40-0x4;
	printf("PE 헤더 시작 : %08X\n",cur = ReadDWORD(fileread,&cur));
	ReadDWORD(fileread,&cur); // PE 시그니처

	////////IMAGE_NT_HEADER///////////

	printf("%08X ",cur);
	printf("Machine : %04X\n",PE.FileHeader.Machine=ReadWORD(fileread,&cur)); // 머신
	printf("%08X ",cur);
	printf("NumberOfSection : %04X\n",PE.FileHeader.NumberOfSections=ReadWORD(fileread,&cur)); // 섹션의 갯수
	cur+=0x4*3;
	
	printf("%08X ",cur);
	printf("SizeOfOptionalHeader : %04X\n",PE.FileHeader.SizeOfOptionalHeader=ReadWORD(fileread,&cur)); // OptionalHeader의 크기
	cur+=0x2;
	printf("------ optional header ----------\n");
	for(int i=0;i<PE.FileHeader.SizeOfOptionalHeader;i++)
	{
		if(i %16 ==0 && i !=0)
			printf("\n");
		if(i %4 ==0 && i%16 !=0) 	
			printf(" ");
		if(i %16 ==0)
			printf("%08X " ,cur+i);
		printf("%02X ",fileread[cur+i]);
	}
	int maxSizeofOHeader = cur+PE.FileHeader.SizeOfOptionalHeader;
	printf("\n\n");
	printf("%08X ",cur);
	printf("Magic : %04X\n",PE.OptionalHeader.Magic=ReadWORD(fileread,&cur)); // 섹션의 갯수
	
	cur += 0x02;
	cur += 0x04*3;
	printf("%08X ",cur);
	printf("AddressOFEntryPoint : %08X \n",PE.OptionalHeader.AddressOfEntryPoint=ReadDWORD(fileread,&cur));
	cur += 0x04*2;
	printf("%08X ",cur);
	printf("ImageBase : %08X \n",PE.OptionalHeader.ImageBase=ReadDWORD(fileread,&cur));
	printf("%08X ",cur);
	printf("SectionAlignment : %08X \n",PE.OptionalHeader.SectionAlignment=ReadDWORD(fileread,&cur));
	printf("%08X ",cur);
	printf("FileAlignment : %08X \n",PE.OptionalHeader.FileAlignment=ReadDWORD(fileread,&cur));
	cur += 0x04*4;
	printf("%08X ",cur);
	printf("PE 의 크기(Sizeof Image) : %08X \n",PE.OptionalHeader.SizeOfImage=ReadDWORD(fileread,&cur));
	printf("%08X ",cur);
	printf("PE 헤더의 크기(Sizeof Header) : %08X \n",PE.OptionalHeader.SizeOfHeaders=ReadDWORD(fileread,&cur));
	cur += 0x04;
	printf("%08X ",cur);
	printf("SubSystem(1.driver 2.GUI 3.CUI) : %04X \n",PE.OptionalHeader.Subsystem=ReadWORD(fileread,&cur));
	cur+= 0x02;
	cur+= 0x04*5;
	printf("%08X ",cur);
	printf("NumberOfRVAAndSizes : %08X\n",PE.OptionalHeader.NumberOfRvaAndSizes=ReadDWORD(fileread,&cur));

	for(int i=0;i<0x10;i++)
	{
		printf("%08X ",cur);
		printf("%s %08X\n",DataDirectoryName[i][0],PE.OptionalHeader.DataDirectory[i].VirtualAddress=ReadDWORD(fileread,&cur));
		printf("%08X ",cur);
		printf("%s %08X\n",DataDirectoryName[i][1],PE.OptionalHeader.DataDirectory[i].Size=ReadDWORD(fileread,&cur));
	}
	cur = maxSizeofOHeader;
	

	printf("\n\n");
	///////섹션 헤더//////////
	printf("---------섹션(Section)헤더--------\n",cur,cur+0x28*PE.FileHeader.NumberOfSections);
	for(int i=0;i<PE.FileHeader.NumberOfSections*0x28;i++)
	{
		if(i %16 ==0 && i !=0)
			printf("\n");
		if(i %4 ==0 && i%16 !=0) 	
			printf(" ");
		if(i %16 ==0)
			printf("%08X " ,cur+i);
		printf("%02X ",fileread[cur+i]);
	}
	printf("\n\n");


	IMAGE_SECTION_HEADER * Section = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER)*PE.FileHeader.NumberOfSections);
	for(int i=0;i<PE.FileHeader.NumberOfSections;i++)
	{
		printf("%08X ",cur);
		printf("섹션 name : ");
		for(int i=0;i<8;i++,cur++)
		{
			printf("%c",fileread[cur]);
		}
		printf("\n------------------------------------\n");
		printf("%08X ",cur);
		printf("메모리에서 이 섹션이 차지하는 크기 %08X\n",Section[i].Misc.PhysicalAddress=ReadDWORD(fileread,&cur));
		printf("%08X ",cur);
		printf("RVA Address %08X\n",Section[i].VirtualAddress=ReadDWORD(fileread,&cur));
		printf("%08X ",cur);
		printf("파일에서 이 섹션이 차지하는 크기 %08X\n",Section[i].SizeOfRawData=ReadDWORD(fileread,&cur));
		printf("%08X ",cur);
		printf("RAW Address %08X\n",Section[i].PointerToRawData=ReadDWORD(fileread,&cur));

		printf("\n\n");
		cur+=0x04*4;
	}
	printf("\n\n");
	printf("--------IID-----------\n");
	WORD NOS =PE.FileHeader.NumberOfSections;
	DWORD FA =PE.OptionalHeader.FileAlignment;

	cur=RVAtoRAW(Section,NOS,FA,PE.OptionalHeader.DataDirectory[1].VirtualAddress);//IMPORT RVA Address 설정

	for(int i=0;i<PE.OptionalHeader.DataDirectory[1].Size;i++)
	{
		if(i %16 ==0 && i !=0)
			printf("\n");
		if(i %4 ==0 && i%16 !=0) 	
			printf(" ");
		if(i %16 ==0)
			printf("%08X " ,cur+i);
		printf("%02X ",fileread[cur+i]);
	}
	printf("\n\n");
	IMAGE_IMPORT_DESCRIPTOR * IID =(IMAGE_IMPORT_DESCRIPTOR *)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR)*PE.OptionalHeader.DataDirectory[1].Size/(0x04*5));
	for(int i=0;i<PE.OptionalHeader.DataDirectory[1].Size/(0x04*5);i++)
	{
		printf("%08X " ,cur);
		printf("OriginalFirstThunk(INT) : %08X\n",IID[i].Characteristics=ReadDWORD(fileread,&cur));
		IID[i].TimeDateStamp=ReadDWORD(fileread,&cur);
		IID[i].ForwarderChain=ReadDWORD(fileread,&cur);
		printf("%08X " ,cur);
		printf("Name(IMPORT library Name) : %08X -->",IID[i].Name=ReadDWORD(fileread,&cur));
		//
		DWORD addressBuffer = cur;
		if(IID[i].Name!=0)
		{
		cur=RVAtoRAW(Section,NOS,FA,IID[i].Name);
		ReadString(fileread,&cur);
		}
		printf("\n");
		//
		cur=addressBuffer;
		printf("%08X " ,cur);
		printf("FirstThunk(IAT) : %08X\n",IID[i].FirstThunk=ReadDWORD(fileread,&cur));
		printf("-- 불러오는 함수 list--\n");
		addressBuffer=cur;
			cur=RVAtoRAW(Section,NOS,FA,IID[i].OriginalFirstThunk);
			DWORD INT =0;
			DWORD IAT =0;
			DWORD saveAddr=0;
			do//read해서 첫번째 주소를 읽는다.)
			{
				INT=ReadDWORD(fileread,&cur);
				if(INT>PE.OptionalHeader.SizeOfImage)
					break;
				
				DWORD addressbuffer2=cur;
				
				if(IAT !=0)
					cur=saveAddr;
				else
					cur=RVAtoRAW(Section,NOS,FA,IID[i].FirstThunk);

					IAT=ReadDWORD(fileread,&cur);
					saveAddr=cur;

					printf("Address : %08X\t",IAT);
				cur=addressbuffer2;
				DWORD addressbuffer3=cur;//지금까지 읽은 주소를 버퍼에서 저장.
					if(cur!=0)
					{
					cur=RVAtoRAW(Section,NOS,FA,INT);
					printf("Hint : %04X\tfunction Name : ",ReadWORD(fileread,&cur));
					ReadString(fileread,&cur);
					printf("\n");
					}
				cur = addressbuffer3;//다시불러온다.
			}while(INT!=0);
			
		cur=addressBuffer;
		printf("\n\n");
	}
	printf("\n\n");
	printf("--------IED-----------\n");
	cur=RVAtoRAW(Section,NOS,FA,PE.OptionalHeader.DataDirectory[0].VirtualAddress);//IMPORT RVA Address 설정

	for(int i=0;i<PE.OptionalHeader.DataDirectory[0].Size;i++)
	{
		if(i %16 ==0 && i !=0)
			printf("\n");
		if(i %4 ==0 && i%16 !=0) 	
			printf(" ");
		if(i %16 ==0)
			printf("%08X " ,cur+i);
		printf("%02X ",fileread[cur+i]);
	}
	printf("\n\n");
	IMAGE_EXPORT_DIRECTORY IED;
	IED.Characteristics=ReadDWORD(fileread,&cur);
	IED.TimeDateStamp=ReadDWORD(fileread,&cur);
	IED.MajorVersion=ReadWORD(fileread,&cur);
	IED.MinorVersion=ReadWORD(fileread,&cur);
	IED.Name=ReadDWORD(fileread,&cur);
	IED.Base=ReadDWORD(fileread,&cur);
	printf("%08X " ,cur);
	printf("Export 할 함수 갯수 : %08X \n",IED.NumberOfFunctions=ReadDWORD(fileread,&cur));
	printf("%08X " ,cur);
	printf("Export 할 이름을 가지는 함수 개수 : %08X \n",IED.NumberOfNames=ReadDWORD(fileread,&cur));
	printf("%08X " ,cur);
	printf("Export 함수 주소 배열 : %08X \n",IED.AddressOfFunctions=ReadDWORD(fileread,&cur));
	printf("%08X " ,cur);
	printf("함수 이름 주소 배열 : %08X \n",IED.AddressOfNames=ReadDWORD(fileread,&cur));
	printf("%08X " ,cur);
	printf("Ordinal 주소 배열 : %08X \n",IED.AddressOfNameOrdinals=ReadDWORD(fileread,&cur));
	
	//1) AddressNames
	int addressBuffer =cur; ////AddressOfName
	cur=RVAtoRAW(Section,NOS,FA,IED.AddressOfNames);
	DWORD AddressOfNames=0;
	WORD AddressOfNameOrdinals=0;
	DWORD AddressOfFunctions=0;
	int saveAddr=0;
	int saveAddr2=0;
	int count=0;
	do
	{
		//2)원하는 함수 찾기
		AddressOfNames=ReadDWORD(fileread,&cur);
		printf("%08X ",AddressOfNames);
		//5) 함수 주소 배열
		int addressBufferEAT = cur;
		if(count ==0)
			cur = RVAtoRAW(Section,NOS,FA,IED.AddressOfFunctions);
		else
			cur = saveAddr2;
			AddressOfFunctions=ReadDWORD(fileread,&cur);
			printf("Address : %08x\t",AddressOfFunctions+PE.OptionalHeader.ImageBase);
			saveAddr2=cur;
		cur = addressBufferEAT;
			//3)Ordinal 배열
			int addressBuffer2=cur;
			if(count ==0)
				cur = RVAtoRAW(Section,NOS,FA,IED.AddressOfNameOrdinals);
			else
				cur =saveAddr;

				printf("Number : %08x\t ",AddressOfNameOrdinals=ReadWORD(fileread,&cur));
				if(AddressOfNameOrdinals > IED.NumberOfFunctions)
					break;
				saveAddr=cur;
				count++;
			cur=addressBuffer2;

		DWORD addressBuffer3 = cur;
			cur = RVAtoRAW(Section,NOS,FA,AddressOfNames);
			printf("functionName : ");
			ReadString(fileread,&cur);
			printf("\n");
		cur = addressBuffer3;
			
	}
	while(AddressOfNames !=0);
	cur=addressBuffer; //end AddressOfName

	free(IID);
	free(Section);
	free(fileread);//동적할당 해제
	return 0;
}
DWORD RVAtoRAW(IMAGE_SECTION_HEADER * ArrOfSection,DWORD NumberOfSection,DWORD FA,DWORD FromRVA)
{
	DWORD result=0;
	for(int i=0;i<NumberOfSection-1/*맨 마지막까지 구별하기 위해서*/;i++)
	{
		if(ArrOfSection[i].VirtualAddress<FromRVA && ArrOfSection[i+1].VirtualAddress>FromRVA)
		{
			if(ArrOfSection[i].PointerToRawData%FA==0)
			result = FromRVA-ArrOfSection[i].VirtualAddress+ArrOfSection[i].PointerToRawData;
			else
			result = FromRVA-ArrOfSection[i].VirtualAddress;
		}
	}
	if(ArrOfSection[NumberOfSection-1].VirtualAddress<FromRVA)
	{
		
			if(ArrOfSection[NumberOfSection-1].PointerToRawData%FA==0)
			result = FromRVA-ArrOfSection[NumberOfSection-1].VirtualAddress+ArrOfSection[NumberOfSection-1].PointerToRawData;
			else
			result = FromRVA-ArrOfSection[NumberOfSection-1].VirtualAddress;
	}
	return result;
}