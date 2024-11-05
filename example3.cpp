#include<stdio.h>
#include<malloc.h>
#include<iostream>
#include<windows.h>
#include<winnt.h>

#define ShellCodeIen  0x12
#define MessageBoxAdder 0x77D507EA
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
    pFile=fopen("F://notepad.exe","rb");
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
    *ppImageBuffer=malloc(pOptionalHeader->SizeOfImage+pOptionalHeader->SectionAlignment);//增加节才加上SectionAligement
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
  
  
  
  
//AddSection
//
LPVOID AddSection(LPVOID pImageBuffer)
{
    if(!pImageBuffer)
    {
        printf("pImageBuffer参数传入失败\n");
        return 0;
    }
  
    PIMAGE_DOS_HEADER pDosHeader=NULL;
    PIMAGE_NT_HEADERS pNTHeader=NULL;
    PIMAGE_FILE_HEADER pFileHeader=NULL;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader=NULL;
    PIMAGE_SECTION_HEADER pSectionHeader=NULL;
    PIMAGE_SECTION_HEADER pNewSectionTable=NULL;
     
    pDosHeader=(PIMAGE_DOS_HEADER)pImageBuffer;
    pNTHeader=(PIMAGE_NT_HEADERS)((DWORD)pImageBuffer+pDosHeader->e_lfanew);
    pFileHeader=(PIMAGE_FILE_HEADER)((DWORD)pNTHeader+4);
    pOptionalHeader=(PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader+20);
    pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pFileHeader->SizeOfOptionalHeader);
  
    //判断文件对齐和内存对齐
    if(pOptionalHeader->FileAlignment==pOptionalHeader->SectionAlignment)
    {
        printf("文件对齐和内存对齐相等\n");
        // 判断是否有足够的空间新增节表
        DWORD SizeOfSectionTable=0x28;
        DWORD FreeBase=((DWORD)pOptionalHeader->SizeOfHeaders-((DWORD)pSectionHeader+pFileHeader->NumberOfSections*SizeOfSectionTable-(DWORD)pImageBuffer));
        if(FreeBase<SizeOfSectionTable*2)
        {
            printf("没有足够的空间新增节表!!!\n");
            free(pImageBuffer);
            return 0;
        }
        printf("有足够的空间新增节表!!!\n");
  
        //修改NumberOfSection
        pFileHeader->NumberOfSections=pFileHeader->NumberOfSections+1;
        printf("NumberOfSection=%d\n",pFileHeader->NumberOfSections);
  
        //修改SizeOfImage
        printf("SizeOfImage=%x\n",pOptionalHeader->SizeOfImage);
        pOptionalHeader->SizeOfImage=pOptionalHeader->SizeOfImage+pOptionalHeader->SectionAlignment;
        printf("SizeOfImage=%x\n",pOptionalHeader->SizeOfImage);
  
        //这里就不同扩大ImageBuffer了，上面已经增加了
  
        //填写新的节表(复制.txt节表然后再修正)
        pNewSectionTable=(PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader+(pFileHeader->NumberOfSections-1)*SizeOfSectionTable);
        //开始复制.text
        memcpy(pNewSectionTable,pSectionHeader,SizeOfSectionTable);
        //修正新的节表
        //循环到倒数第二个节表
        for(int i=1;i<pFileHeader->NumberOfSections-1;i++,pSectionHeader++)
        {
            printf("%d\n",i);
        }
        pNewSectionTable->Misc.VirtualSize=pOptionalHeader->SectionAlignment;
        printf("%x\n",pNewSectionTable->Misc.VirtualSize);
        pNewSectionTable->VirtualAddress=pSectionHeader->VirtualAddress+pSectionHeader->SizeOfRawData;
        printf("%x\n",pNewSectionTable->VirtualAddress);
        pNewSectionTable->SizeOfRawData=pOptionalHeader->SectionAlignment;
        printf("%x\n",pNewSectionTable->SizeOfRawData);
        pNewSectionTable->PointerToRawData=pSectionHeader->PointerToRawData+pSectionHeader->SizeOfRawData;
        printf("%x\n",pNewSectionTable->PointerToRawData);  
        printf("新的节表修正完成!!!\n");
  
        return pImageBuffer;
    }
    else
    {
        printf("内存对齐和文件对齐不相等\n");
        printf("文件对齐和内存对齐相等\n");
        // 判断是否有足够的空间新增节表
        DWORD SizeOfSectionTable=0x28;
        DWORD FreeBase=((DWORD)pOptionalHeader->SizeOfHeaders-((DWORD)pSectionHeader+pFileHeader->NumberOfSections*SizeOfSectionTable-(DWORD)pImageBuffer));
        if(FreeBase<SizeOfSectionTable*2)
        {
            printf("没有足够的空间新增节表!!!\n");
            free(pImageBuffer);
            return 0;
        }
        printf("有足够的空间新增节表!!!\n");
  
        //修改NumberOfSection
        pFileHeader->NumberOfSections=pFileHeader->NumberOfSections+1;
        printf("NumberOfSection=%d\n",pFileHeader->NumberOfSections);
  
        //修改SizeOfImage
        printf("SizeOfImage=%x\n",pOptionalHeader->SizeOfImage);
        pOptionalHeader->SizeOfImage=pOptionalHeader->SizeOfImage+pOptionalHeader->SectionAlignment;
        printf("SizeOfImage=%x\n",pOptionalHeader->SizeOfImage);
  
        //这里就不用扩大ImageBuffer了，上面已经增加了
        //填写新的节表(复制.txt节表然后再修正)
        pNewSectionTable=(PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader+(pFileHeader->NumberOfSections-1)*SizeOfSectionTable);
        //开始复制.text
        memcpy(pNewSectionTable,pSectionHeader,SizeOfSectionTable);
        //修正新的节表
        //循环到倒数第二个节表
        for(int i=1;i<pFileHeader->NumberOfSections-1;i++,pSectionHeader++)
        {
            printf("%d\n",i);
        }
        pNewSectionTable->Misc.VirtualSize=pOptionalHeader->SectionAlignment;
        printf("%x\n",pNewSectionTable->Misc.VirtualSize);
        DWORD RawSize=pSectionHeader->SizeOfRawData;
        printf("%x????\n",RawSize);
        //这里因为文件对齐和内存对齐不一样，所以需要对齐
        while(RawSize%pOptionalHeader->SectionAlignment!=0)
        {
            RawSize++;
            //printf("RawSize=%x\n",RawSize);
        }
        pNewSectionTable->VirtualAddress=pSectionHeader->VirtualAddress+RawSize;
        printf("%x\n",pNewSectionTable->VirtualAddress);
        pNewSectionTable->SizeOfRawData=pOptionalHeader->SectionAlignment;
        printf("%x\n",pNewSectionTable->SizeOfRawData);
        pNewSectionTable->PointerToRawData=pSectionHeader->PointerToRawData+pSectionHeader->SizeOfRawData;
        printf("%x\n",pNewSectionTable->PointerToRawData);  
        printf("新的节表修正完成!!!\n");
  
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
    printf("numberofsection=%d\n",pFileHeader->NumberOfSections);
    printf("%x\n",pSectionHeader->Misc.VirtualSize);
    printf("%x\n",pSectionHeader->VirtualAddress);
    printf("%x\n",pSectionHeader->SizeOfRawData);
    printf("%x\n",pSectionHeader->PointerToRawData);
     
    //循环到最后一个节表
    DWORD SizeOfBuffer=pSectionHeader->PointerToRawData+pSectionHeader->SizeOfRawData;
    printf("SizeOfBuffer=%x\n",SizeOfBuffer);
  
  
    //开辟空间
    *ppBuffer=malloc(SizeOfBuffer);
    if(!*ppBuffer)
    {
        printf("开辟Buffer空间失败\n");
        return 0;
    }
     
    memset(*ppBuffer,0,SizeOfBuffer);
  
    //复制头
    memcpy(*ppBuffer,pImageBuffer,pOptionalHeader->SizeOfHeaders);
    //复制节表
    pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pFileHeader->SizeOfOptionalHeader);
    printf("woc\n");
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
    FILE* fpw=fopen("F://notepad_test.exe","wb");
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
    LPVOID* ppFileBuffer=&pFileBuffer;
    LPVOID pImageBuffer=NULL;
    LPVOID* ppImageBuffer=&pImageBuffer;
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
  
  
  
    //调用AddSection函数
    pImageBuffer=AddSection(pImageBuffer);
  
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
  
  
  
    return 0;
  
  
  
}