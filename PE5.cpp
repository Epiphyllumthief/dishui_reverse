#pragma warning(disable:4996)
#include<iostream>
#include<windows.h>
#include<winnt.h> 
#define ShellCode_Len 0x12
#define MessageBoxAdder 0x769CAC60
//0x1008750 0x7453250B
BYTE ShellCode[]=
{
0x6A,00,0x6A,00,0x6A,00,0x6A,00,
0xE8,00,00,00,00,
0xE9,00,00,00,00
};
int Fsize(FILE *fp){
    fseek(fp,0,SEEK_END);
    int size = ftell(fp);
    fseek(fp,0,SEEK_SET);
    return size;
}

DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer){
    FILE* fp;
    fp =  fopen(lpszFile,"rb");
    int F_size = Fsize(fp);
    LPVOID pTempFileBuffer = NULL;
    pTempFileBuffer  = malloc(F_size);
    
    if(!pTempFileBuffer){
		printf("1分配内存空间失败!\n");
		fclose(fp); 
		return 0;
	}
	
	size_t Read = fread(pTempFileBuffer,F_size,1,fp);
	if(!Read){
		printf("2读取文件失败\n"); 
		fclose(fp);
		return 0;
    }
	
	fclose(fp);
	*pFileBuffer = pTempFileBuffer;
    pTempFileBuffer = NULL;
    return F_size;
}

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer){
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    LPVOID pTempImageBuffer = NULL;

    if(pFileBuffer == NULL){
        printf("获取PE文件失败!\n");
        return 0;
    }

    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    
    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
        printf("不是有效的MZ文件!\n");
        return 0;
    }

    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);

    if(pNTHeader->Signature != IMAGE_NT_SIGNATURE){
        printf("不是有效的PE文件!\n");
        return 0;
    } 
    pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader+0x4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    pTempImageBuffer = malloc(pOptionHeader->SizeOfImage);
    if(!pTempImageBuffer){
        printf("申请内存失败!\n");
        return 0;
    }

    memset(pTempImageBuffer,0,pOptionHeader->SizeOfImage);
    memcpy(pTempImageBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);

    PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
    for(int i = 0;i < pPEHeader->NumberOfSections;i++,pTempSectionHeader++){
        memcpy((void*)((DWORD)pTempImageBuffer+pTempSectionHeader->VirtualAddress),
            ((void*)(DWORD)pFileBuffer+pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
    }

    *pImageBuffer = pTempImageBuffer;
    pTempImageBuffer = NULL;
    return pOptionHeader->SizeOfImage;
}

LPVOID ADDSection(LPVOID pImageBuffer){
    PIMAGE_DOS_HEADER pDos_header = NULL;
	PIMAGE_NT_HEADERS pNT_header = NULL;
	PIMAGE_FILE_HEADER pPE_header = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOption_header = NULL;
	PIMAGE_SECTION_HEADER pSection_header = NULL;
	PIMAGE_SECTION_HEADER pLastSection_header = NULL;
	PIMAGE_SECTION_HEADER pNewSection_header = NULL;
	LPVOID pFirstSection_header = NULL;
	BOOL flag = false;
 
	//算出ImageBuffer中的dos头nt头pe头节表地址
	pDos_header = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNT_header = (PIMAGE_NT_HEADERS)((DWORD)pDos_header + pDos_header->e_lfanew);
	pPE_header = (PIMAGE_FILE_HEADER)((DWORD)pNT_header + 4);
	pOption_header = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPE_header + IMAGE_SIZEOF_FILE_HEADER);
	pFirstSection_header = (PIMAGE_SECTION_HEADER)((DWORD)pOption_header + pPE_header->SizeOfOptionalHeader);
	pSection_header = (PIMAGE_SECTION_HEADER)((DWORD)pOption_header + pPE_header->SizeOfOptionalHeader);
    LPVOID pLastDos = LPVOID((DWORD)pImageBuffer + sizeof(IMAGE_DOS_HEADER));

    for(int i = 0;i < pPE_header->NumberOfSections; i++,pSection_header++);
    pLastSection_header = pSection_header;
    pNewSection_header = pSection_header + 1;
    PBYTE pTemp = (PBYTE)pNewSection_header;
    if((DWORD)pImageBuffer + pOption_header->SizeOfHeaders - (DWORD)pNewSection_header >= 2*IMAGE_SIZEOF_FILE_HEADER){
       /* for(int i = 0; i < 80 ;i++,pTemp++){
            if(*pTemp){
               // printf("need to move header\n");
                flag = TRUE;
                break;
            }
        }*/
    }else {
        flag = TRUE;
    }

    if(flag){
        printf("need to move header\n");
        memcpy(pLastDos, pNT_header, (DWORD)pNewSection_header - (DWORD)pNT_header);
        pDos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);
        pNT_header = (PIMAGE_NT_HEADERS)((DWORD)pDos_header + pDos_header->e_lfanew);
	    pPE_header = (PIMAGE_FILE_HEADER)((DWORD)pNT_header + 4);
	    pOption_header = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPE_header + IMAGE_SIZEOF_FILE_HEADER);
	    pFirstSection_header = (PIMAGE_SECTION_HEADER)((DWORD)pOption_header + pPE_header->SizeOfOptionalHeader);
	    pSection_header = (PIMAGE_SECTION_HEADER)((DWORD)pOption_header + pPE_header->SizeOfOptionalHeader);
        for(int i = 0;i < pPE_header->NumberOfSections; i++,pSection_header++){
            printf("%s\n",pSection_header->Name);
        }
        pLastSection_header = pSection_header;
        //pNewSection_header = pSection_header + 1;
        LPVOID pTemp = (LPVOID)((DWORD)pLastSection_header);
        memset(pLastSection_header,0,IMAGE_SIZEOF_SECTION_HEADER*3);
    }
    ++pPE_header->NumberOfSections;
    pOption_header->SizeOfImage = (DWORD)pOption_header->SizeOfImage + 0x1000;
    memcpy(pLastSection_header, pFirstSection_header,IMAGE_SIZEOF_SECTION_HEADER);
    strcpy((char*)pLastSection_header->Name, (char*)".tttt");
    pLastSection_header->Misc.VirtualSize = pOption_header->SectionAlignment;
    pSection_header--;
    DWORD RawSize = pSection_header->SizeOfRawData;
    printf("RawSize: 0x%x",RawSize);
    for(int i=1;RawSize % pOption_header->SectionAlignment != 0;i++,RawSize++);
    printf("pSection_header->VirtualAddress RawSize: 0x%x 0x%x\n",pSection_header->VirtualAddress ,RawSize);
    pLastSection_header->VirtualAddress = pSection_header->VirtualAddress + RawSize;
    pLastSection_header->SizeOfRawData = pOption_header->SectionAlignment;
    pLastSection_header->PointerToRawData = pSection_header->PointerToRawData + pSection_header->SizeOfRawData;
    printf("success add section\n");
    return pImageBuffer;
}

LPVOID ShellCode_insert(LPVOID pImageBuffer){
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    DWORD* ShellCodeBegin = NULL;

    if(!pImageBuffer)
    {
        printf("pImageBuffer Open Failed\n");
        return 0;
    }

    pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pPEHeader)+20);
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);
    for(int i=1;i<pPEHeader->NumberOfSections;i++,pSectionHeader++);
    printf("pSectionName:%s\n",pSectionHeader->Name);
    if(pSectionHeader->Misc.VirtualSize < ShellCode_Len){
        printf("节表空间不足\n");
        free(pImageBuffer);
        return 0;
    }

    if(pOptionHeader->SectionAlignment == pOptionHeader->FileAlignment){
        printf("SectionAlignment == FileAlignment\n");
        ShellCodeBegin = (DWORD*)(pSectionHeader->VirtualAddress+(DWORD)pImageBuffer);
        if(!memcpy(ShellCodeBegin,ShellCode,ShellCode_Len)){
            printf("Copy ShellCodeBegin Failed\n");
            return 0;
        }
        DWORD Calladdr = (DWORD)((DWORD)MessageBoxAdder-((DWORD)pOptionHeader->ImageBase+(DWORD)ShellCodeBegin-(DWORD)pImageBuffer+0xD));
        if(!Calladdr){
            printf("set call failed\n");
            return 0;
        }
        *(DWORD*)((BYTE*)ShellCodeBegin + 0x9) = Calladdr;
        printf("set call success!\n");

        DWORD JMPaddr = (DWORD)((DWORD)pOptionHeader->AddressOfEntryPoint-((DWORD)ShellCodeBegin+ShellCode_Len-(DWORD)pImageBuffer));
        if(!JMPaddr){
            printf("set jmp failed\n");
            return 0;
        }
        *(DWORD*)((BYTE*)ShellCodeBegin + 0xE) = JMPaddr;
        printf("set jmp success!\n");
        pOptionHeader->AddressOfEntryPoint = (DWORD)ShellCodeBegin -(DWORD)pImageBuffer;
        printf("OEP=%x\n",pOptionHeader->AddressOfEntryPoint);
        printf("OEP ok\n");
    }else {
        printf("SectionAlignment != FileAlignment\n");
        //pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);
        ShellCodeBegin = (DWORD*)(pSectionHeader->PointerToRawData+(DWORD)pImageBuffer);
        printf("ShellCodeBegin : 0x%x\n",ShellCodeBegin);
        if(!memcpy(ShellCodeBegin,ShellCode,ShellCode_Len)){
            printf("Copy ShellCodeBegin Failed\n");
            return 0;
        }
        DWORD Calladdr = (DWORD)((DWORD)MessageBoxAdder-((DWORD)pOptionHeader->ImageBase+(DWORD)ShellCodeBegin-(DWORD)pImageBuffer+0xD));
        if(!Calladdr){
            printf("set call failed\n");
            return 0;
        }
        *(DWORD*)((BYTE*)ShellCodeBegin + 0x9) = Calladdr;
        printf("set call success!\n");

        DWORD JMPaddr = (DWORD)((DWORD)pOptionHeader->AddressOfEntryPoint-((DWORD)ShellCodeBegin+ShellCode_Len-(DWORD)pImageBuffer));
        if(!JMPaddr){
            printf("set jmp failed\n");
            return 0;
        }
        *(DWORD*)((BYTE*)ShellCodeBegin + 0xE) = JMPaddr;
        printf("set jmp success!\n");
        pOptionHeader->AddressOfEntryPoint = (DWORD)ShellCodeBegin -(DWORD)pImageBuffer;
        printf("OEP=%x\n",pOptionHeader->AddressOfEntryPoint);
        printf("OEP ok\n");
    }return pImageBuffer;
}

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer){
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    LPVOID pTempNewBuffer = NULL;
    DWORD sizeOfFile = 0;
    DWORD numberOfSection = 0;

    if(pImageBuffer == NULL){
        printf("获取PE内存失败!\n");
        return 0;
    }

    pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    
    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
        printf("不是有效的MZ文件!\n");
        return 0;
    }

    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer+pDosHeader->e_lfanew);

    if(pNTHeader->Signature != IMAGE_NT_SIGNATURE){
        printf("不是有效的PE文件!\n");
        return 0;
    }

    pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader+0x4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    //pTempImageBuffer = malloc(pOptionHeader->SizeOfImage);
    sizeOfFile = pOptionHeader->SizeOfHeaders;
    //memcpy(pTempNewBuffer,pImageBuffer,sizeOfFile);

    for(int i=0;i<pPEHeader->NumberOfSections;i++)
        sizeOfFile += pSectionHeader[i].SizeOfRawData;
    printf("0x%x sizeoffile!\n",sizeOfFile);
    printf("debug\n");
    pTempNewBuffer = malloc(sizeOfFile);
    printf("debug\n");
    if(!pTempNewBuffer){
        printf("申请内存失败!\n");
        return 0;
    }

    memset(pTempNewBuffer,0,sizeOfFile);
    memcpy(pTempNewBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
    printf("debug\n");
    PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
    for(int i = 0;i < pPEHeader->NumberOfSections;i++,pTempSectionHeader++){
        printf("%d\n",i);
        memcpy((void*)((DWORD)pTempNewBuffer+pTempSectionHeader->PointerToRawData),
            ((void*)(DWORD)pImageBuffer+pTempSectionHeader->VirtualAddress),pTempSectionHeader->SizeOfRawData);
        printf("%X  --> PoniterToRadata\r\n",pTempSectionHeader->PointerToRawData);
        printf("%X  --> VirtualAddress\r\n",pTempSectionHeader->VirtualAddress);
        printf("%X  --> VirtualSize\r\n",pTempSectionHeader->Misc.VirtualSize);
    }

    *pNewBuffer = pTempNewBuffer;
    pTempNewBuffer = NULL;
    return sizeOfFile;
}

BOOL MemeryToFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile){
    FILE* fp = NULL;
    fp = fopen(lpszFile, "wb+");
    if(!fp){
        return false;
    }
    fwrite(pMemBuffer,size,1,fp);
    fclose(fp);
    fp=NULL;
    return true;
}

void init(){
    DWORD Size = 0;
    BOOL flag = FALSE;
    LPVOID pFileBuffer = NULL;
    LPVOID pImageBuffer = NULL;
    LPVOID pNewBuffer = NULL;
    char* FilePath_In = "F://notepad.exe ";

    Size = ReadPEFile("F://notepad.exe",&pFileBuffer);
    if(!pFileBuffer || !Size){
        printf("Read File Failed!");
        return ;
    }else {
        printf("Size %x\r\n",Size);
        printf("pFilBuffer %d\r\n",pFileBuffer);
        printf("pFileBuffer-length %d\r\n",sizeof(pFileBuffer));
        printf("pFileBuffer-address %x\r\n",&pFileBuffer);
    }

    Size = CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
    if(!pImageBuffer){
        printf("FileBuffer--->ImageBuffer Filed\r\n");
        free(pFileBuffer);
        return;
    }
    else{
        printf("pImageBuffer--%d\r\n",pImageBuffer);
        printf("pImageBuffer-address--%x\r\n",&pImageBuffer);
        printf("Size    --%x\r\n",Size);
    }
    pImageBuffer = ADDSection(pImageBuffer);
    pImageBuffer = ShellCode_insert(pImageBuffer);

    Size = CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
    if (!pNewBuffer){
        printf("ImageBuffer->NewBuffer Failed\r\n");
        free(pFileBuffer);
        free(pImageBuffer);
        return;
    }
    else{
        printf("Size    --%x\r\n",Size);
    }    
    flag = MemeryToFile(pNewBuffer,Size,"F://notepad_new6.exe");
    if(flag){
        printf("存盘成功!\n");
        return ;
    }
    free(pFileBuffer);
    free(pImageBuffer);
    free(pNewBuffer);
}

int main(){
    init();
    printf("We're done here,have a nice day!\n");
    return 0;
}