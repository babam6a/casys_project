SRC := $(wildcard ./test/*.c)

all : apager dpager hpager apager_back_to_back

apager : apager.c
	gcc -o apager apager.c

dpager : dpager.c
	gcc -o dpager dpager.c

hpager : hpager.c
	gcc -o hpager hpager.c

apager_back_to_back : apager_back_to_back.c
	gcc -o apager_back_to_back apager_back_to_back.c

test : $(SRC)
	gcc --static -o $@ $^

clean :
	rm apager dpager hpager apager_back_to_back