all:
	gcc -Wall -DHAVE_LIBSPARSE -DHAVE_SHA	*.c -o imgtool -I. -lz -g2

linux64:
	gcc -DHAVE_LIBSPARSE	 -DHAVE_SHA *.c -o imgtool.ELF64 -I. -lz 
linux32:
	gcc -m32 -DHAVE_LIBSPARSE	 -DHAVE_SHA *.c -o imgtool.ELF32 -I. -lz 

dist:
	tar zcvf imgtool.tgz Makefile *.c *.h sparse  imgtool.* imgtool
