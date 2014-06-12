CC = gcc
CFLAGS = -ggdb -Wall
LDFLAGS = -lpcap -lcrypto -lpthread -lrt -lssl
SOURCES = main.c mask.c util.c covert.c server.c client.c
//SOURCES = main.c mask.c util.c covert.c server.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = runner

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@
	sudo chown root:root $(EXECUTABLE)
	sudo chmod +s $(EXECUTABLE)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)
