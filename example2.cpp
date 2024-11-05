#include<iostream>
#include<stdio.h>
#include<windows.h>
#include<malloc.h>
#define ShellCodeIen 0x12
#define MessageBoxAdder 0x7553AC60
//0x1008750 0x7453250B
BYTE ShellCode[]=
{
0x6A,00,0x6A,00,0x6A,00,0x6A,00,
0xE8,00,00,00,00,
0xE9,00,00,00,00
};

//
//FileBuffer函数
DWORD ReadPEFile(LPVOID* ppFileBuffer)
{
    FILE* pFile=NULL;
    DWORD SizeFileBuffer=0;
    pFile=fopen("F:\\notepad.exe","rb");
    if(!pFile)
    {
        printf("打开notepad失败\n");
        return 0;
    }
    //获取文件大小
    fseek(pFile,0,SEEK_END);
    SizeFileBuffer=ftell(pFile);
    fseek(pFile,0,SEEK_SET);
    if(!SizeFileBuffer)
    {
        printf("读取文件大小失败\n");
        return 0;
    }
    //开辟空间
    *ppFileBuffer=malloc(SizeFileBuffer);
    if(!*ppFileBuffer)
    {
        printf("开辟空间失败\n");
        fclose(pFile);
        return 0;
    }
    //复制数据
    size_t n=fread(*ppFileBuffer,SizeFileBuffer,1,pFile);
    if(!n)
    {
        printf("复制数据失败\n");
        free(*ppFileBuffer);
        fclose(pFile);
        return 0;
    }
    fclose(pFile);
    return SizeFileBuffer;
}
 
 
 
///
//FileBuffer--->ImgaeBuffer
DWORD FileBufferToImageBuffer(LPVOID pFileBuffer,LPVOID* ppImageBuffer)
{
    PIMAGE_DOS_HEADER pDosHeader=NULL;
    PIMAGE_NT_HEADERS pNTHeader=NULL;
    PIMAGE_FILE_HEADER pFileHeader=NULL;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader=NULL;
    PIMAGE_SECTION_HEADER pSectionHeader=NULL;
 
    if(!pFileBuffer)
    {
        printf("FileBuffer函数调用失败\n");
        return 0;
    }
    printf("%x\n",pFileBuffer);
//判断是否是PE文件
    pDosHeader=(PIMAGE_DOS_HEADER)pFileBuffer;
    if(pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
    {
        printf("不是有效的MZ标志\n");
        return 0;
    }
 
    pNTHeader=(PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
    {
        printf("不是有效的PE标志\n");
        return 0;
    }
 
    pFileHeader=(PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
    
    pOptionalHeader=(PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader+20);
 
 
    //开辟ImageBuffer空间
    *ppImageBuffer=malloc(pOptionalHeader->SizeOfImage);
    if(!*ppImageBuffer)
    {
        printf("开辟ImageBuffer空间失败");
        return 0;
    }
    printf("SizeOfImage%x\n",pOptionalHeader->SizeOfImage);
    //malloc清零
    memset(*ppImageBuffer,0,pOptionalHeader->SizeOfImage);
 
    //复制Headers
    printf("SizeOfHeader%x\n",pOptionalHeader->SizeOfHeaders);
    memcpy(*ppImageBuffer,pDosHeader,pOptionalHeader->SizeOfHeaders);
 
    //循环复制节表
    pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pFileHeader->SizeOfOptionalHeader);
    for(int i=1;i<=pFileHeader->NumberOfSections;i++,pSectionHeader++)
    {
        memcpy((LPVOID)((DWORD)*ppImageBuffer+pSectionHeader->VirtualAddress),(LPVOID)((DWORD)pFileBuffer+pSectionHeader->PointerToRawData),pSectionHeader->SizeOfRawData);
        printf("%d\n",i);
    }
    printf("拷贝完成\n");
    return pOptionalHeader->SizeOfImage;
}
 
 LPVOID shellCode(LPVOID pImageBuffer)
{
PIMAGE_DOS_HEADER pDosHeader = NULL;
PIMAGE_NT_HEADERS pNTHeader = NULL;
PIMAGE_FILE_HEADER pPEHeader = NULL;
PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
PIMAGE_SECTION_HEADER pSectionHeader = NULL;
PBYTE ShellCodeBegin = NULL;
if(!pImageBuffer)
{
printf("pImageBuffer han shu diao yong shi bai\n");
return 0;
}

pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer+pDosHeader->e_lfanew);
pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pPEHeader)+20);
pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pPEHeader->SizeOfOptionalHeader);

/* for(int j=0;j<pPEHeader->NumberOfSections;j++)
{
if((pSectionHeader[j].SizeOfRawData - pSectionHeader[j]Misc.VirtualSize) < shellCodeIen)
{
printf("第%d个节表空间不足\n",j);
free(pImageBuffer);
return 0;
}
} */
    if((pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize) < ShellCodeIen)
    {
        printf("节表空间不足\n");
        free(pImageBuffer);
        return 0;
    }
    printf("SizeOfRaw=%x\n",pSectionHeader->SizeOfRawData);
    printf("VirtualSize=%x\n",pSectionHeader->Misc.VirtualSize);
    printf("nei cun chong zu");
    if(pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
    {
        printf("SectionAlignment == FileAlignment\n");
        ShellCodeBegin=(PBYTE)(pSectionHeader->VirtualAddress+pSectionHeader->Misc.VirtualSize+(DWORD)pImageBuffer);
    if(!memcpy(ShellCodeBegin,ShellCode,ShellCodeIen))
    {
        printf("dai ma chu bu jia ru shi bai\n");
        return 0;
    }
        printf("代码初步加入成功!\n");

//E8
    DWORD CallAdd = (DWORD)((DWORD)MessageBoxAdder-((DWORD)pOptionalHeader->ImageBase+(DWORD)ShellCodeBegin+0xD-(DWORD)pImageBuffer));
    if(!CallAdd)
    {
        printf("ERROR E8\n");
        return 0;
    }
    *(PDWORD)(ShellCodeBegin+0x9) = CallAdd;
    printf("E8 ok\n");

//E9
    DWORD JmpAdd=(DWORD)((DWORD)pOptionalHeader->AddressOfEntryPoint-((DWORD)ShellCodeBegin+ShellCodeIen-(DWORD)pImageBuffer));
    if(!JmpAdd)
    {
        printf("ERROR E9\n");
        return 0;
    }
    *(PDWORD)(ShellCodeBegin+0xE) = JmpAdd;
    printf("E9 ok\n");
    pOptionalHeader->AddressOfEntryPoint = (DWORD)ShellCodeBegin -(DWORD)pImageBuffer;
    printf("OEP=%x\n",pOptionalHeader->AddressOfEntryPoint);
    printf("OEP ok\n");
    printf("finish");
    return pImageBuffer;
}
else
    {
        printf("SectionAlignment != FileAlignment\n");
        pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pPEHeader->SizeOfOptionalHeader);
        ShellCodeBegin=(PBYTE)(pSectionHeader->VirtualAddress+pSectionHeader->Misc.VirtualSize+(DWORD)pImageBuffer);
        if(!memcpy(ShellCodeBegin,ShellCode,ShellCodeIen))
        {
            printf("dai ma chu bu jia ru shi bai\n");
            return 0;
        }
    printf("代码初步加入成功!\n");

//E8
    DWORD CallAdd = (DWORD)((DWORD)MessageBoxAdder-((DWORD)pOptionalHeader->ImageBase+(DWORD)ShellCodeBegin+0xD-(DWORD)pImageBuffer));
    printf("!Message: 0x%X pOptionalHeader->ImageBase : 0x%X ShellCodeBegin : 0x%X pImageBuffer : 0x%X  CallAdd : 0x%X\n",(DWORD)MessageBoxAdder,(DWORD)pOptionalHeader->ImageBase,(DWORD)ShellCodeBegin,(DWORD)pImageBuffer,CallAdd);
    if(!CallAdd)
    {
        printf("ERROR E8\n");
        return 0;
    }
    *(PDWORD)(ShellCodeBegin+0x9) = CallAdd;
    printf("E8 ok\n");

    DWORD JmpAdd=(DWORD)((DWORD)pOptionalHeader->AddressOfEntryPoint-((DWORD)ShellCodeBegin+ShellCodeIen-(DWORD)pImageBuffer));
    if(!JmpAdd)
    {
        printf("ERROR E9\n");
        return 0;
    }
    *(PDWORD)(ShellCodeBegin+0xE) = JmpAdd;
    printf("E9 ok\n");
    pOptionalHeader->AddressOfEntryPoint = (DWORD)ShellCodeBegin -(DWORD)pImageBuffer;
    printf("OEP=%x\n",pOptionalHeader->AddressOfEntryPoint);
    printf("OEP ok\n");
    printf("finish");
    return pImageBuffer;
    }
}
 
//ImageBufferToFileBuffer
DWORD ImageBufferToFileBuffer(LPVOID pImageBuffer,LPVOID* ppBuffer)
{
    PIMAGE_DOS_HEADER pDosHeader=NULL;
    PIMAGE_NT_HEADERS pNTHeader=NULL;
    PIMAGE_FILE_HEADER pFileHeader=NULL;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader=NULL;
    PIMAGE_SECTION_HEADER pSectionHeader=NULL;
 
    if(!pImageBuffer)
    {
        printf("error");
        return 0;
    }
 
    pDosHeader=(PIMAGE_DOS_HEADER)pImageBuffer;
    pNTHeader=(PIMAGE_NT_HEADERS)((DWORD)pImageBuffer+pDosHeader->e_lfanew);
    pFileHeader=(PIMAGE_FILE_HEADER)((DWORD)pNTHeader+4);
    pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + 20);
    pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pFileHeader->SizeOfOptionalHeader);
 
    //得到FileBuffer的大小
    for(int i=1;i<pFileHeader->NumberOfSections;i++,pSectionHeader++)
    {
        printf("%d\n",i);
    }
    
    //循环到最后一个节表
    DWORD SizeOfBuffer=pSectionHeader->PointerToRawData+pSectionHeader->SizeOfRawData;
 
    //开辟空间
    *ppBuffer=malloc(SizeOfBuffer);
    if(!*ppBuffer)
    {
        printf("开辟Buffer空间失败\n");
        return 0;
    }
    printf("SizeOfBuffer%x\n",SizeOfBuffer);
    memset(*ppBuffer,0,SizeOfBuffer);
 
    //复制头
    memcpy(*ppBuffer,pImageBuffer,pOptionalHeader->SizeOfHeaders);
    //复制节表
    pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pFileHeader->SizeOfOptionalHeader);
    for(int j=1;j<=pFileHeader->NumberOfSections;j++,pSectionHeader++)
    {
        printf("%d\n",j);
        memcpy((LPVOID)((DWORD)*ppBuffer+pSectionHeader->PointerToRawData),(LPVOID)((DWORD)pImageBuffer+pSectionHeader->VirtualAddress),pSectionHeader->SizeOfRawData);
    }
    printf("拷贝完成\n");
    return SizeOfBuffer;
 
 
}
 
 
 
 
//存贮到新的exe
BOOL MemeryToFile(LPVOID pBuffer,DWORD SizeOfBuffer)
{
    FILE* fpw=fopen("F:\\notepad_new2.exe","wb");
    if(!fpw)
    {
        printf("fpw error");
        return false;
    }
    if (fwrite(pBuffer, 1, SizeOfBuffer, fpw) == 0)
    {
        printf("fpw fwrite fail");
        return false;
    }
    fclose(fpw);            
    fpw = NULL;
    printf("success\n");
    return true;
 
}

int main()
{
    LPVOID pFileBuffer=NULL;
    LPVOID* ppFileBuffer=&pFileBuffer;    //定义二级指针
    LPVOID pImageBuffer=NULL;
    LPVOID* ppImageBuffer=&pImageBuffer;  //定义二级指针
    DWORD SizeOfFileBuffer=0;
    DWORD SizeOfImageBuffer=0;
    DWORD SizeOfBuffer=0;
 
    LPVOID pBuffer=NULL;
    LPVOID* ppBuffer=&pBuffer;
 
 
    //调用filebuffer函数
    SizeOfFileBuffer=ReadPEFile(ppFileBuffer);
    if(!SizeOfFileBuffer)
    {
        printf("FileBuffer函数调用失败 \n");
        return 0;
    }
    pFileBuffer=*ppFileBuffer;
 
 
 
    //调用FileBufferToImageBuffer函数
    SizeOfBuffer=FileBufferToImageBuffer(pFileBuffer,ppImageBuffer);
 
    if(!SizeOfBuffer)
    {
        printf("调用FileBufferToImageBuffer函数失败");
        return 0;
    }
    pImageBuffer=shellCode(pImageBuffer);
    //调用ImageBufferToBuffer
    SizeOfBuffer=ImageBufferToFileBuffer(pImageBuffer,ppBuffer);
    pBuffer=*ppBuffer;
    if(!SizeOfBuffer)
    {
        printf("SizeOfBuffer error");
        return 0;
    }
 
    //调用MemeryToFile
    if(MemeryToFile(pBuffer,SizeOfBuffer)==false)
    {
        printf("end");
        return 0;
    }
 
 
 
 
 
}