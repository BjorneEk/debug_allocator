TARGET=debug_allocator

# Files
SOURCE_DIR:=src
SOURCE_FILES:=$(wildcard $(SOURCE_DIR)/*.c $(SOURCE_DIR)/*/*.c)
HEADER_FILES:=$(wildcard $(SOURCE_DIR)/*.h $(SOURCE_DIR)/*/*.h)
OBJ:=${SOURCE_FILES:.c=.o}

# Compiler
CC=gcc
CFLAGS=-I$(SOURCE_DIR)
LIBS:=

# Rules
%.o: %.c $(HEADER_FILES)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	$(RM) $(OBJ)
	$(RM) $(TARGET)
