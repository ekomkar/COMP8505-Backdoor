CC = gcc
CFLAGS = -ggdb -Wall -pedantic
LDFLAGS = -lpcap -lcrypto -lpthread -lrt -lssl
SOURCES = main.c mask.c server.c util.c client.c covert.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = runner

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@
	sudo chown root:rootr $(EXECUTABLE)
	sudo chmod +s $(EXECUTABLE)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)