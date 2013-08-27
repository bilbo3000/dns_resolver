myresolver : myresolver.o 
	gcc myresolver.o -o myresolver  

myresolver.o : myresolver.c
	gcc -c myresolver.c

clean: 
	rm -rf ./myresolver
	rm -rf ./myresolver.o
