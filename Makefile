SRC = $(wildcard *.c)
TEST_SRC = $(filter-out test/utils.c, $(wildcard test/*.c))

all : loader tests

loader : $(SRC)
	for i in $(SRC); do \
		gcc -o $$(basename $$i .c) $$i; \
	done
	
tests : $(TEST_SRC)
	for i in $(TEST_SRC); do \
		gcc --static -include ./test/utils.c -o $$(basename $$i .c) $$i; \
	done

clean :
	rm $(basename $(SRC) .c) $(basename $(TEST_SRC) .c)