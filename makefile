procnanny: procnanny.o memwatch.o
	gcc -Wall -std=c99 -o procnanny procnanny.o  memwatch.o -lm -g

procnanny.o: procnanny.c memwatch.h
	gcc -ansi -Wall -std=c99 -c -g -DLINUX -D_GNU_SOURCE -DMEMWATCH -DMW_STDIO procnanny.c

memwatch.o: memwatch.c memwatch.h
	gcc -std=c99 -Wall -c memwatch.c -DMEMWATCH -DMW_STDIO 

clean:
	-rm -f *.o procnanny core