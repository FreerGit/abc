CC = gcc
CFLAGS = -std=c2x -Wall -Wextra -Iinclude
ASAN = -fsanitize=address -fno-omit-frame-pointer
INC_DIR = -I include/stx/stx 
LFLAGS = -lwolfssl -luring

BUILD ?= debug

ifeq ($(BUILD), release)
	ASAN =  
	CFLAGS += -O3 -s -DNDEBUG -march=native -flto
else
	ASAN = -fsanitize=address -fno-omit-frame-pointer
	CFLAGS += -g
endif

SRC_DIR = src
OBJ_DIR = build

# Find all .c files in the src dir
SRCS = $(wildcard $(SRC_DIR)/*.c)

# Create .o file paths in build dir
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

TARGET = bin

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(ASAN) $(INC_DIR) -o $@ $^ $(LFLAGS)

# Compile .c to .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(ASAN) $(INC_DIR) -c -o $@ $< $(LFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean