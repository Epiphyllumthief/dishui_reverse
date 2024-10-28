#pragma warning(disable:4996)
#include<iostream>
#include<windows.h>
#include<winnt.h> 

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
    pTempNewBuffer = malloc(sizeOfFile);
    if(!pTempNewBuffer){
        printf("申请内存失败!\n");
        return 0;
    }

    memset(pTempNewBuffer,0,sizeOfFile);
    memcpy(pTempNewBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);

    PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
    for(int i = 0;i < pPEHeader->NumberOfSections;i++,pTempSectionHeader++){
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

    
    flag = MemeryToFile(pImageBuffer,Size,"F://notepad_new.exe");
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