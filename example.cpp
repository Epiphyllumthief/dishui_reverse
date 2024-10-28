
#include <string.h>
#include <windows.h>
#include <stdlib.h>
/*#include <tchar.h>
#include <iostream>
#include <stdio.h>
*/

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

 // globle.cpp: implementation of the globle class.
//
//////////////////////////////////////////////////////////////////////

//定义一个全局变量
BYTE ShellCode[] =
{
    0x6A,00,0x6A,00,0x6A,00,0x6A,00,
    0xE8,00,00,00,00,
    0xE9,00,00,00,00
};

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
//ExeFile->FileBuffer  返回值为计算所得文件大小

DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{
    //下面有个IN和OUT，大致意思就是参数的类型传入进来之后不进行宏扩展；
    //啥也不干，即使理解成干，也是扩展成空白，这个是C++语法中允许的；
    //LPSTR  ---->  typedef CHAR *LPSTR, *PSTR; 意思就是char* 指针；在WINNT.H头文件里面
    FILE* pFile = NULL;
    //定义一个FILE结构体指针，在标准的Stdio.h文件头里面
    //可参考：
    DWORD fileSize = 0;
    // typedef unsigned long       DWORD;  DWORD是无符号4个字节的整型
    LPVOID pTempFileBuffer = NULL;
    //LPVOID ---->  typedef void far *LPVOID;在WINDEF.H头文件里面；别名的void指针类型

    //打开文件
    pFile = fopen(lpszFile,"rb"); //lpszFile是当作参数传递进来
    if (!pFile)
    {
        printf("打开文件失败!\r\n");
        return 0;
    }
    /*
    关于在指针类型中进行判断的操作，下面代码出现的情况和此一样，这里解释下：
    1.因为指针判断都要跟NULL比较，相当于0，假值，其余都是真值
    2.if(!pFile)和if(pFile == NULL), ----> 为空，就执行语句；这里是两个等于号不是一个等于号
    3.if(pFile)就是if(pFile != NULL), 不为空，就执行语句；
    */

    //读取文件内容后，获取文件的大小
    fseek(pFile,0,SEEK_END);
    fileSize = ftell(pFile);
    fseek(pFile,0,SEEK_SET);

    /*
    fseek 通过使用二进制的方式打开文件，移动文件读写指针的位置,在stdio.h头文件里

    int fseek(FILE * stream, long offset, int fromwhere);

    上面是fseek的函数原型
    第一个参数stream 为文件指针
    第二个参数offset 为偏移量，整数表示正向偏移，负数表示负向偏移
    第三个参数fromwhere 为指针的起始位置,设定从文件的哪里开始偏移,可能取值为：SEEK_CUR，SEEK_END，SEEK_SET
    SEEK_SET 0 文件开头
    SEEK_CUR 1 当前读写的位置
    SEEK_END 2 文件尾部

    下面是相关用法和例子：
　　fseek(fp,100L,0);把fp指针移动到离文件开头100字节处；
　　fseek(fp,100L,1);把fp指针移动到离文件当前位置100字节处；
    fseek(fp,100L,2);把fp指针退回到离文件结尾100字节处。
    fseek(fp,0,SEEK_SET);将读写位置移动到文件开头;
    fseek(fp,0,SEEK_END);将读写位置移动到文件尾时;
    fseek(fp,100L,SEEK_SET);将读写位置移动到离文件开头100字节处；
    fseek(fp,100L,SEEK_CUR);将读写位置移动到离文件当前位置100字节处；
    fseek(fp,-100L,SEEK_END);将读写指针退回到离文件结尾100字节处；
    fseek(fp,1234L,SEEK_CUR);把读写位置从当前位置向后移动1234字节;
    fseek(fp,0L,2);把读写位置移动到文件尾;
    其中 --->  L后缀表示长整数

    ftell()用于返回文件当前指针指向的位置，与fseek配合可以算出文件元素数据总数。
    参考：http://c.biancheng.net/cpp/html/2519.html

    ftell()函数用来获取文件读写指针的当前位置，其原型为：long ftell(FILE * stream); 同样在stdio.h头文件里
    参数：stream 为已打开的文件指针。
    */

    //动态申请内存空间
    pTempFileBuffer = malloc(fileSize);

    /*
    参考：http://c.biancheng.net/cpp/html/137.html
    原型：void* malloc (size_t size);
    size_t ---> typedef unsigned int size_t; 无符号整型别名是size_t
    void*  ---> 函数的返回值类型是 void* ；void并不是说没有返回值或者返回空指针，而是返回的指针类型未知;
    所以在使用 malloc() 时通常需要进行强制类型转换，将 void 指针转换成我们希望的类型;
    例如：char *ptr = (char *)malloc(10);  //分配10个字节的内存空间，用来存放字符
    参数说明 ---> size 为需要分配的内存空间的大小，以字节（Byte）计。
    函数说明 ---> malloc()在堆区分配一块指定大小的内存空间，用来存放数据。这块内存空间在函数执行完成后不会被初始化;
    它们的值是未知的，所以分配完成内存之后需要初始化；
    返回值:分配成功返回指向该内存的地址，失败则返回 NULL。
    */

    if (!pTempFileBuffer)
    {
        printf("内存分配失败!\r\n");
        fclose(pFile);
        return 0;
    }

    //根据申请到的内存空间，读取数据

    size_t n = fread(pTempFileBuffer,fileSize,1,pFile);
    if (!n)
    {
        printf("读取数据失败!\r\n");
        free(pTempFileBuffer);   // 释放内存空间
        fclose(pFile);            // 关闭文件流
        return 0;
    }

    //数据读取成功，关闭文件
    *pFileBuffer = pTempFileBuffer;  // 将读取成功的数据所在的内存空间的首地址放入指针类型pFileBuffer
    pTempFileBuffer = NULL;  // 初始化清空临时申请的内存空间
    fclose(pFile);           // 关闭文件
    return fileSize;         // 返回获取文件的大小
}

//CopyFileBuffer --> ImageBuffer

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer)
{
    //LPVOID ---->  typedef void far *LPVOID;在WINDEF.H头文件里面；别名的void指针类型
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    LPVOID pTempImageBuffer = NULL;
    /*
    上面都是PE里面的相关结构体类型，使用其类型进行自定义变量，并初始化值为NULL
    PIMAGE_DOS_HEADER ---> 指向结构体，别名为这两个 IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER
    PIMAGE_NT_HEADERS ---> 指向结构体，typedef PIMAGE_NT_HEADERS32    PIMAGE_NT_HEADERS;
    PIMAGE_FILE_HEADER ---> 指向结构体，别名为这两个 IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
    PIMAGE_OPTIONAL_HEADER32 ---> 指向结构体，别名为这两个 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
    PIMAGE_SECTION_HEADER ---> 指向结构体，别名为这两个 IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
    */

    if (pFileBuffer == NULL)
    {
        printf("FileBuffer 获取失败!\r\n");
        return 0;
    }

    //判断是否是有效的MZ标志
    if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
    {
        printf("无效的MZ标识\r\n");
        return 0;
    }
    /*
    IMAGE_DOS_SIGNATURE 这个在头文件WINNT.H里面，对应是个无参数宏；
    #define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
    在宏扩展的时候就会替换为0x5A4D ，然后根据架构的不同进行排序存储，分大端和小端模式；
    使用上面方式进行比对是否是有效的MZ头是非常有效；
    而且IMAGE_DOS_SIGNATURE存储的值是两个字节，刚好就是PWORD ---> typedef WORD near *PWORD;
    所以在进行比较的时候需要强制类型转换为相同的类型进行比较
    */

    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    //这里的定义，就相当于已经确定了，其头肯定是MZ了，然后强制转换类型为PIMAGE_DOS_HEADER，就是Dos头

    //判断是否是有效的PE标志
    if (*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
    {
        printf("无效的PE标记\r\n");
        return 0;
    }
    /*
    IMAGE_NT_SIGNATURE  ---> #define IMAGE_NT_SIGNATURE   0x00004550  // PE00
    上述同样是个宏扩展，在头文件WINNT.H里面；
    在进行比对的时候因为在Dos头里面有个值是 e_lfanew 对应的时候DWORD类型，所以在进行指针相加的时候
    需要先进行强制类型转换，然后相加，即移动指针位置；然后最终需要比对的结果是0x4550站两个字节
    所以又要强制转换类型为PWORD；
    */
    //定位NT头
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    //上面偏移完成之后pFileBuffer的指针偏移到了NT头---> pNTHeader
    //****************************************************************************************
    //定位PE文件头
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
    //根据PE头的结构体内容，PE文件头位置在NT头首地址偏移4个字节即可得到pPEHeader
    //****************************************************************************************
    //定位可选PE头
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
    /*
    要得到可选PE的首地址位置，就根据上面得到的PE文件头位置里面的IMAGE_SIZEOF_FILE_HEADER来定位；
    IMAGE_SIZEOF_FILE_HEADER也是个宏扩展，里面字节描述了PE文件头的大小是20个字节；
    #define IMAGE_SIZEOF_FILE_HEADER  20，所以只要在PE文件头的首地址偏移20个字节即可移动到可选PE头；
    指针相加的时候，此处的类型依然是DWORD
    */
    //****************************************************************************************
    //第一个节表指针
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    /*
    这里要移动到第一个节表指针的首地址，就需要根据上面标准PE文件头中的SizeOfOptionalHeader获取具体可选PE
    头的大小，然后根据这个大小进行偏移即可；
    */
    //****************************************************************************************

    /*
    到了节表的首地址位置之后，因为需要将FileBuffer复制到ImageBuffer，这个过程中，节表之前的Dos头，NT头
    PE文件头，可选PE头，她们的大小都是不变的，所以定位出来之后，到后面的操作中直接复制即可，而节表不一样
    她在FileBuffer状态和ImageBuffer状态是不相同的，她们节表之间复制转换到ImageBuffer是需要拉长节表，所以
    在操作的时候是需要确定FileBuffer到ImageBuffer之后ImageBuffer的大小是多少，而这个大小，已经在可选PE头
    里面的某一个值中已经给出来了 ---> SizeOfImage ;
    注意：FileBuffer和ImageBuffer都是在内存中的展示，只不过FileBuffer是使用winhex等类似的形式打开查看其
    二进制的形式，而ImageBuffer则是双击打开应用程序，将其加载至内存中显示的二进制的形式；
    */
    //****************************************************************************************

    //根据SizeOfImage申请新的内存空间
    pTempImageBuffer = malloc(pOptionHeader->SizeOfImage);

    if (!pTempImageBuffer)
    {
        printf("再次在堆中申请一块内存空间失败\r\n");
        return 0;
    }

    //因为下面要开始对内存空间进行复制操作，所以需要初始化操作，将其置为0，避免垃圾数据，或者其他异常
    //初始化新的缓冲区
    memset(pTempImageBuffer,0,pOptionHeader->SizeOfImage);
    /*
    参考：http://c.biancheng.net/cpp/html/157.html

    在头文件string.h里面

    void* memset( void* ptr,int value,size_t num );
    memset()函数用来将指定内存的前n个字节设置为特定的值;

    参数说明：
    ptr     为要操作的内存的指针;
    value     为要设置的值;既可以向value传递int类型的值,也可以传递char类型的值,int和char可以根据ASCII码相互转换;
    num        为ptr的前num个字节,size_t就是unsigned int。
    函数说明：memset()会将ptr所指的内存区域的前num个字节的值都设置为value,然后返回指向ptr的指针;
    */
    //****************************************************************************************

    //根据SizeOfHeaders大小的确定，先复制Dos头
    memcpy(pTempImageBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
    /*
    参考：http://c.biancheng.net/cpp/html/155.html

    在头文件string.h里面

    void* memcpy (void* dest,const void* src,size_t num);
    memcpy()函数功能用来复制内存的；她会复制src所指向内容的首地址，作为起始位置，然后偏移num个字节到dest所指的内存地址
    的位置；此函数有个特征就是，她并不关心被复制的数据类型，只是逐字节地进行复制，这给函数的使用带来了很大的灵活性，
    可以面向任何数据类型进行复制；

    需要注意的是：
    dest 指针要分配足够的空间，也就是要大于等于num字节的空间，如果没有分配足够的空间会出现错误；
    dest和src所指的内存空间不能重叠（如果发生了重叠，使用 memmove() 会更加安全）。

    所以上面的代码的含义如下：
    (1)pDosHeader ---> 是指向pFileBuffer的首地址，也就是内存复制的时候从这里开始；
    (2)pTempImageBuffer  ---> 这里是表示上面要复制的目的，要把内容复制到这块内存来；
    (3)pOptionHeader->SizeOfHeaders  ---> 这里表示复制多大的内容到pTempImageBuffer里面去；
    (4)从上面看来我们就知道复制到目标pOptionHeader->SizeOfHeaders所在的内存空间一定要比pTempImageBuffer大；
    */
    //****************************************************************************************

    //上面把已经确定的头都复制好了，那么下面就可以开始复制节的里面的内容，因为节不仅仅是一个，所以需要用到for循环进行操作
    //根据节表循环copy节的内容
    PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
    //定义一个临时节表的指针
    for (int i=0;i<pPEHeader->NumberOfSections;i++,pTempSectionHeader++)
    {
        memcpy((void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress),
            (void*)((DWORD)pFileBuffer + pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
    }
    /*
    上面的大概操作就是根据标准PE文件头里面的值 NumberOfSections确定有几个节，然后不断的计算并增加指针偏移位置，不停的复制

    PointerToRawData   ---> 节在文件中的偏移地址；
    VirtualAddress     ---> 节在内存中的偏移地址;
    SizeOfRawData      ---> 节在文件中对齐后的尺寸;

    (void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress)   ---> Dest（目的地）
    上面我们已经知道了函数memcpy是怎么复制操作的，所以这里我们依依解释下：
    首先我们知道，上面展示的是目的地，而且我们的目的是要从FileBuffer节内容复制到ImageBuffer节的内容，
    那么要使用到的是文件被双击打开之后在内存中的偏移地址，这个地址就是VirtualAddress；这里举个例子:
    正常打开notepad.exe,然后使用winhex加载这个notepad.exe的内存数据，同时使用PE解析工具得到两个值的信息如下：
    可选PE头 ---> ImageBase   ---> 0x01000000
    第一个节表显示的VirtualAddress  ---> 00001000
    上面两个值相加就得到了文件被打开在内存中第一个节的真实数据的起始位置 ---> 0x01001000
    查看winhex对应的地址，确认是对的；

    (void*)((DWORD)pFileBuffer + pTempSectionHeader->PointerToRawData)      ---> Src（源复制的起始内存地址）
    同样是上面的例子：
    PointerToRawData是节在文件中的偏移地址，而我们知道，在文件中和在内存中是不一样的，因为在内存中有ImageBase的说法，
    但在文件中没有，所以她的起始位置就是文件存储在硬盘的时候使用winhex打开的开头位置，为这里同样使用winhex以二进制的形式
    打开notepad.exe（非双击打开），发现文件的起始位置是0x00000000，同时使用PE解析工具确认出了PointerToRawData的值
    PointerToRawData  ---> 0x00000400 ; 起始位置为0x00000000 ,她们相加就得到第一个节表的起始位置为0x00000400
    查看winhex对应的地址，确认是对的；
    所以这里总结下来的Src，就是内存复制的时候，从这个偏移地址开始拿数据开始复制；

    pTempSectionHeader->SizeOfRawData
    这里就是告诉我们上面复制要复制多大的内容到 (void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress)
    SizeOfRawData ---> 节在文件中对齐后的尺寸;
    例子还是以上面的为例：
    通过PE解析工具确认SizeOfRawData的大小为：0x00007800

    总结：
    memcpy((void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress),
    (void*)((DWORD)pFileBuffer + pTempSectionHeader->PointerToRawData),
    pTempSectionHeader->SizeOfRawData);

    上面代码就是在文件中的形式找到要复制的位置0x00000400的起始位置开始复制，要复制0x00007800个字节大小，也就是从
    0x00000400这个地址开始向后偏移7800个字节，将这些数据复制到文件双击被打开时候的内存地址0x01001000为起点向后覆盖复制
    完成即可，为这里测试算了下；0x00000400+0x00007800=0x00007C00 ; 0x00007C00这个地址刚好是第二个节的PointerToRawData
    这样就可以很好的理解for循环对第二个节的复制；
    */

    //****************************************************************************************
    //返回数据
    *pImageBuffer = pTempImageBuffer;
    //将复制好后节的首地址保存到指针pImageBuffer中
    pTempImageBuffer = NULL;
    //初始化清空临时使用的pTempImageBuffer

    return pOptionHeader->SizeOfImage;
}

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer)
{
    //下面大部分操作都是跟上面一样的，这里就不再赘述了
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    LPVOID pTempNewBuffer = NULL;
    DWORD sizeOfFile = 0;
    DWORD numberOfSection = 0;

    if (pImageBuffer == NULL)
    {
        printf("缓冲区指针无效\r\n");
    }
    //判断是否是有效的MZ标志
    if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
    {
        printf("不是有效的MZ头\r\n");
        return 0;
    }
    pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    //判断是否是有效的PE标志
    if (*((PDWORD)((DWORD)pImageBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
    {
        printf("不是有效的PE标志\r\n");
        return 0;
    }
    //NT头地址
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
    //标准PE文件头
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
    //可选PE头
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
    //第一个节表地址
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    //计算文件需要的空间--最后一个节的文件偏移+节对齐后的长度
    /*
    numberOfSection = pPEHeader->NumberOfSections;
    pSectionHeader = pSectionHeader+(numberOfSection-1);
    sizeOfFile = (pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize + pOptionHeader->FileAlignment);
    */

    sizeOfFile = pOptionHeader->SizeOfHeaders;
    //使用winhex打开notepad.exe 是0x00000400，这是第一个节之前的所有大小
    for(DWORD i = 0;i<pPEHeader->NumberOfSections;i++)
    {
        sizeOfFile += pSectionHeader[i].SizeOfRawData;  // pSectionHeader[i]另一种加法
    }
    /*
    上面的for循环大概意思就是基于几个节的数量依次循环叠加sizeOfFile的值；因为SizeOfRawData是文件中对齐后的大小；
    所以循环计算如下：
    sizeOfFile = 0x00000400 + 0x00007800 = 0x00007C00
    sizeOfFile = 0x00007C00 + 0x00000800 = 0x00008400
    sizeOfFile = 0x00008400 + 0x00008000 = 0x00010400

    */

    //根据SizeOfImage申请新的空间
    pTempNewBuffer = malloc(sizeOfFile);

    if (!pTempNewBuffer)
    {
        printf("申请内存空间失败\r\n");
        return 0;
    }
    //初始化新的缓冲区
    memset(pTempNewBuffer,0,sizeOfFile);
    //根据SizeOfHeaders 先copy头
    memcpy(pTempNewBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
    //根据节表循环复制节
    //PIMAGE_SECTION_HEADER pTempSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader);
    PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
    for (int j=0;j<pPEHeader->NumberOfSections;j++,pTempSectionHeader++)
    {
        /*memcpy((void*)((DWORD)pTempNewBuffer + pTempSectionHeader->PointerToRawData),
        (void*)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress),
        pTempSectionHeader->SizeOfRawData);*/
        //PointerToRawData节区在文件中的偏移,VirtualAddress节区在内存中的偏移地址,SizeOfRawData节在文件中对齐后的尺寸
        memcpy((PDWORD)((DWORD)pTempNewBuffer+pTempSectionHeader->PointerToRawData),
        (PDWORD)((DWORD)pImageBuffer+pTempSectionHeader->VirtualAddress),
        pTempSectionHeader->SizeOfRawData);
        printf("%X  --> PoniterToRadata\r\n",pTempSectionHeader->PointerToRawData);
        printf("%X  --> VirtualAddress\r\n",pTempSectionHeader->VirtualAddress);
        printf("%X  --> VirtualSize\r\n",pTempSectionHeader->Misc.VirtualSize);
    }

    //返回数据
    *pNewBuffer = pTempNewBuffer;
    pTempNewBuffer = NULL;
    return sizeOfFile;
  }

BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile)
{
    FILE* fp = NULL;
    fp = fopen(lpszFile, "wb+");
    if (!fp)  //  这里我刚开始写漏了一个等于号，变成复制NULL了，导致错误
//    if(fp == NULL)  可以这么写，没问题
    {
        return FALSE;
    }
    fwrite(pMemBuffer,size,1,fp);
    fclose(fp);
    fp = NULL;
    return TRUE;
}
/*
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva)
{
    DWORD dwFOAValue = 0;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    //判断指针是否有效
    if (!pFileBuffer)
    {
        printf("FileBuffer 指针无效\r\n");
        return dwFOAValue;
    }
    //判断是否是有效的MZ标志
    if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
    {
        printf("不是有效的MZ标志\r\n");
        return dwFOAValue;
    }
    //为需要用到的指针赋值
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);

    //判断dwRva所处的节

    //计算与节开始位置的差

    //该节文件中的偏移+差 == 该值在文件中的偏移
    return 0;
}
*/

void Fun()
{
    DWORD    Size            =    0;        //用来接收数据大小
    BOOL    isok            =    FALSE;        //用来接收写入磁盘是否成功
    LPVOID    pFileBuffer        =    NULL;    //用来接收缓冲区的首地址
    LPVOID    pImageBuffer    =    NULL;
    LPVOID    pNewBuffer        =    NULL;

    //File---> FileBuffer
    Size = ReadPEFile(FilePath_In,&pFileBuffer);    //调用函数读取文件数据
    if(!pFileBuffer || !Size)
    {
        printf("File-> FileBuffer失败");
        return;
    }
    else
    {
        printf("Size %x\r\n",Size);
        printf("pFilBuffer %d\r\n",pFileBuffer);
        printf("pFileBuffer-length %d\r\n",sizeof(pFileBuffer));
        printf("pFileBuffer-address %x\r\n",&pFileBuffer);
    }

    //FileBuffer---> ImageBuffer
    Size = CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);

    if(!pImageBuffer)
    {
        printf("FileBuffer--->ImageBuffer Filed\r\n");
        free(pFileBuffer);
        return;
    }
    else
    {
        printf("pImageBuffer--%d\r\n",pImageBuffer);
        printf("pImageBuffer-address--%x\r\n",&pImageBuffer);
        printf("Size    --%x\r\n",Size);
    }

    //ImageBuffer ---> NewBuffer
    Size = CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
    if (!pNewBuffer)
    {
        printf("ImageBuffer->NewBuffer Failed\r\n");
        free(pFileBuffer);
        free(pImageBuffer);
        return;
    }
    else
    {
        printf("Size    --%x\r\n",Size);
    }

    //NewBuffer --> 文件
    isok = MemeryTOFile(pNewBuffer,Size,FilePath_Out);
    if (isok)
    {
        printf("存盘成功\r\n");
        return;
    }
 
    //释放内存
    free(pFileBuffer);
    free(pImageBuffer);
    free(pNewBuffer);
}

int main(int argc, char* argv[])
{
    Fun();
    printf("Hello World That Fuck Successfully!\r\n");
    return 0;
}