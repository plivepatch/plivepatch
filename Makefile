MAIN = main
TARGETS = 
TARGETSO = patch

ALL : plivepatch func $(TARGETSO) $(MAIN)

CC = gcc
FLAGS = -w -Wall
SHARED := -fPIC --shared


define MAKE_IMPL
$(1) : $(1).c
	$$(CC) $$(FLAGS) -o $$@ $$^
endef

$(foreach v, $(TARGETS), $(eval $(call MAKE_IMPL, $(v))))

patch : patch.c
	$(CC) $(FLAGS) $(SHARED) -o $@.so $^

func : func.c
	$(CC) $(FLAGS) $(SHARED) -I. -o lib$@.so $^

plivepatch : plivepatch.c
	$(CC) $(FLAGS) -o $@ $^ -ldl

$(MAIN) : main.c
	$(CC) $(FLAGS) -o $@ $^ -ldl -L. -lfunc
	
clean :
	rm plivepatch libfunc.so $(MAIN) $(foreach v, $(TARGETSO), $(v).so)

install :
	cp libfunc.so /usr/lib/libfunc.so
