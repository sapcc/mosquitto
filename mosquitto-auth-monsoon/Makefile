NAME      = mosquitto_auth_plugin_monsoon

CFLAGS    = -Wall -Werror -fPIC
ifdef MOSQUITTO_DIR
INCLUDES = -I$(MOSQUITTO_DIR)/src -I$(MOSQUITTO_DIR)/lib
endif
LDFLAGS   = -lldap -lmosquitto

all: $(NAME).so

$(NAME).so: $(NAME).o
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -shared $^ -o $@ $(LIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(INCLUDES) $(DEBUG) $< -o $@

clean:
	rm -f *.o *.so
