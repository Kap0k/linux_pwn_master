###Problem
--  
```sub_400A6E("\nWhich filter do you want to apply?");  
  v4 = sub_400B30();
  if ( v4 > 2 )
    return puts("Invalid filter.");
  ((void (__fastcall *)(__int64, __int64, int))*(&off_602090 + v4))(
    v3,
    a1 + 264 * v5 + 8LL,
    *(unsigned __int8 *)(264 * v5 + 4LL + a1));
  return puts("\nDone!");  
```  
问题还是比较明显的，v4不能大于2，但是可以为负数，导致可以输入16Byte的长整数，调用text段任意函数。  
  
###Exploit  
-- 

问题是调用什么函数。  
看一下GOT表，能调的函数就这些了。  
   
```
0                 dq offset stru_601E28
.got.plt:0000000000602008 qword_602008    dq 0                    ; DATA XREF: sub_4006A0↑r
.got.plt:0000000000602010 qword_602010    dq 0                    ; DATA XREF: sub_4006A0+6↑r
.got.plt:0000000000602018 off_602018      dq offset _exit         ; DATA XREF: __exit↑r
.got.plt:0000000000602020 off_602020      dq offset puts          ; DATA XREF: _puts↑r
.got.plt:0000000000602028 off_602028      dq offset fread         ; DATA XREF: _fread↑r
.got.plt:0000000000602030 off_602030      dq offset fclose        ; DATA XREF: _fclose↑r
.got.plt:0000000000602038 off_602038      dq offset setbuf        ; DATA XREF: _setbuf↑r
.got.plt:0000000000602040 off_602040      dq offset printf        ; DATA XREF: _printf↑r
.got.plt:0000000000602048 off_602048      dq offset memset        ; DATA XREF: _memset↑r
.got.plt:0000000000602050 off_602050      dq offset __libc_start_main
.got.plt:0000000000602050                                         ; DATA XREF: ___libc_start_main↑r
.got.plt:0000000000602058 off_602058      dq offset fgets         ; DATA XREF: _fgets↑r
.got.plt:0000000000602060 off_602060      dq offset fopen         ; DATA XREF: _fopen↑r
.got.plt:0000000000602068 off_602068      dq offset atoi          ; DATA XREF: _atoi↑r
.got.plt:0000000000602070 off_602070      dq offset fwrite        ; DATA XREF: _fwrite↑r
.got.plt:0000000000602070 _got_plt        ends

```  
  
这里就可以利用一般被我们忽略的函数，setbuf,这个函数的作用是给文件描述符设置缓冲区，被设置缓冲区后我们从指定文件描述符读或写数据时，将由缓冲区缓存，另外，setbuf函数默认设置的缓冲区大小为8192Byte.这里setbuf作参数的话，正巧能够为/dev/null的描述符设置默认大小的缓冲区。Setbuf示例见我上传的example.   
Setbuf利用文章:[https://paper.seebug.org/450/](https://paper.seebug.org/450/) 

  
OK，我们观察一下代码逻辑，在使用add message的时候，消息会被分配到栈上，这里没有溢出。  
  
``` 
{
  signed int i; // [rsp+1Ch] [rbp-14h]

  for ( i = 0; i <= 4 && *(_BYTE *)(264 * i + a1); ++i )
    ;
  if ( i == 5 )
    return puts("Too many messages :P");
  printf("\nInput your contents: ");
  *(_BYTE *)(264 * i + 4LL + a1) = sub_400AA1(264 * i + 8LL + a1, 256);
  *(_BYTE *)(264 * i + a1) = 1;
  return puts("\nDone!");
}
```  
  
一共可以分配5个这样的块，每个大小为256Byte,那么我们这样分配：  
1 256  
2 256  
3 256  
4 256  
5 256  
随后，我们利用setbuf函数，把/dev/null的缓冲区设置为5的位置，再利用filter，向缓冲区中写数据，那么  
setbuf(fd,5)  
filter(1)  
filter(2)  
即可将栈溢出掉，后面就是ROP了。  
ROP的构造有一个地方略麻烦，需要找一个读入onegadget的gadget.泄露libc后跳过去就OK，问题是这个gadget在哪里?  
仔细观察下代码逻辑就会发现了。另外，这个ROP含有\x0a,需要利用XORfilter过滤一下。  
  
####我为什么木有做出这题  
--   
STEP1  
比赛时并不知道setbuf的作用，于是我按照我的思路去做这题，在送入负数调函数时我选择的函数是`memset`，这是因为memset能够在堆上首堆块存入XORFilter的内容，于是我想到利用memset在堆上构造连续的字符串，从而printf泄露出关键地址，于是有:  

```
gdb-peda$ heap
heapbase : 0x17a7000
gdb-peda$ x/300gx 0x17a7000
0x17a7000:	0x0000000000000000	0x0000000000000231
0x17a7010:	0xc8c8c8c8c8c8c8c8	0xc8c8c8c8c8c8c8c8
0x17a7020:	0xc8c8c8c8c8c8c8c8	0xc8c8c8c8c8c8c8c8
0x17a7030:	0xc8c8c8c8c8c8c8c8	0xc8c8c8c8c8c8c8c8
0x17a7040:	0xc8c8c8c8c8c8c8c8	0xc8c8c8c8c8c8c8c8
0x17a7050:	0xc8c8c8c8c8c8c8c8	0xc8c8c8c8c8c8c8c8
0x17a7060:	0xc8c8c8c8c8c8c8c8	0xc8c8c8c8c8c8c8c8
0x17a7070:	0xc8c8c8c8c8c8c8c8	0x00007fdbcfc5f540
0x17a7080:	0x0000000000000003	0x0000000000000000
0x17a7090:	0x0000000000000000	0x00000000017a70f0
0x17a70a0:	0xffffffffffffffff	0x0000000000000000
0x17a70b0:	0x00000000017a7100	0x0000000000000000
0x17a70c0:	0x0000000000000000	0x0000000000000000
0x17a70d0:	0x00000000ffffffff	0x0000000000000000
0x17a70e0:	0x0000000000000000	0x00007fdbcfc5d6e0
0x17a70f0:	0x0000000000000000	0x0000000000000000
```  
  
0x17a7078的位置就是libc上某个偏移了，也就有了onegadget。  
同理，我泄露了堆栈地址，但问题是如何跳过去？  
还是回到  
  
```
  ((void (__fastcall *)(__int64, __int64, int))*(&off_602090 + v4))(
    v3,
    a1 + 264 * v5 + 8LL,
    *(unsigned __int8 *)(264 * v5 + 4LL + a1));
  return puts("\nDone!");  
```  
  
如果负数足够大的话，是可以产生整数溢出的这里，在32位下我成功用这个方法拿到了shell，但是因为这里被转成了int_64，所以很遗憾，我的不用setbuf的方法在这里行不通。Offset - (1<<64)
