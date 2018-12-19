CC = g++
OPENSSL_INCLUDE_PATH = /usr/local/opt/openssl/include
OPENSSL_LIB_PATH = /usr/local/opt/openssl/lib

OUTPUT_DIR = ./bin/
PATCHER_DIR = ./navicat-patcher/
KEYGEN_DIR = ./navicat-keygen/
keygen_output = $(OUTPUB_DIR)navicat-keygen

PATCHER_HEADER = \
$(PATCHER_DIR)FileMapper.hpp \
$(PATCHER_DIR)Helper.hpp \
$(PATCHER_DIR)RSACipher.hpp \
$(PATCHER_DIR)Solutions.hpp

PATCHER_SOURCE = \
$(PATCHER_DIR)Helper.cpp \
$(PATCHER_DIR)main.cpp \
$(PATCHER_DIR)Solution0.cpp \
$(PATCHER_DIR)Solution1.cpp

PATCHER_BINARY = $(OUTPUT_DIR)navicat-patcher

KEYGEN_HEADER = \
$(KEYGEN_DIR)Helper.hpp \
$(KEYGEN_DIR)RSACipher.hpp \
$(KEYGEN_DIR)DESCipher.hpp \
$(KEYGEN_DIR)NavicatKeygen.hpp

KEYGEN_SOURCE = \
$(KEYGEN_DIR)Helper.cpp \
$(KEYGEN_DIR)main.cpp

KEYGEN_BINARY = $(OUTPUT_DIR)navicat-keygen

patcher: $(PATCHER_HEADER) $(PATCHER_SOURCE)
	@if [ ! -d $(OUTPUT_DIR) ]; then mkdir -p $(OUTPUT_DIR); fi
	$(CC) -std=c++11 -O2 -I$(OPENSSL_INCLUDE_PATH) -L$(OPENSSL_LIB_PATH) -lcrypto $(PATCHER_SOURCE) -o $(PATCHER_BINARY)

keygen: $(KEYGEM_HEADER) $(KEYGEN_SOURCE)
	@if [ ! -d $(OUTPUT_DIR) ]; then mkdir -p $(OUTPUT_DIR); fi
	$(CC) -std=c++11 -O2 -I$(OPENSSL_INCLUDE_PATH) -L$(OPENSSL_LIB_PATH) -lcrypto $(KEYGEN_SOURCE) -o $(KEYGEN_BINARY)

all: patcher keygen
	@echo 'Done.'

.PHONY: all

clean:
ifeq ($(wildcard $(PATCHER_BINARY)), $(PATCHER_BINARY))
	rm $(PATCHER_BINARY)
endif

ifeq ($(wildcard $(KEYGEN_BINARY)), $(KEYGEN_BINARY))
	rm $(KEYGEN_BINARY)
endif

