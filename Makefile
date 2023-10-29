all : apager dpager apager_back_to_back

apager : apager.c
	gcc -o apager apager.c

dpager : dpager.c
	gcc -o dpager dpager.c

apager_back_to_back : apager_back_to_back.c
	gcc -o apager_back_to_back apager_back_to_back.c

clean :
	rm apager dpager apager_back_to_back