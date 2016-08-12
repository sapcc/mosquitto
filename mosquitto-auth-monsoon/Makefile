NAME       := mosquitto_auth_plugin_monsoon
OS         := $(shell uname -s)
CFLAGS     := -Wall -Werror -Wno-deprecated-declarations -fPIC
LDFLAGS    := -lldap -lmosquitto

ifeq ($(OS),Darwin)
#https://github.com/eclipse/mosquitto/issues/244
LDFLAGS    += -undefined dynamic_lookup
endif

all: $(NAME).so

$(NAME).so: $(NAME).c 
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -shared $^ -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

test_runner: tests.c $(NAME).c
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) tests.c -o test_runner

.PHONY: test
test: test_runner
	./test_runner

clean:
	rm -f *.so test_runner
