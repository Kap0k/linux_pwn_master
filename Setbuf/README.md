Setbuf这个题考察了Setbuf函数在漏洞利用中的作用，这是容易忽略的一个点。  
1.一般pwn题目都要Setbuf(stdin(out),0);  
2.Setbuf函数默认缓冲区长度为4096/8192  
3.如果Setbuf调用不当，容易造成长度溢出问题。  
