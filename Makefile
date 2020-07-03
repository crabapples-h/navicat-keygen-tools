CC = g++
UNAME = $(shell uname)

ifeq ($(UNAME),Darwin)
	OPENSSL_INCLUDE_PATH = /usr/local/opt/openssl@1.1/include
	OPENSSL_LIB_PATH = /usr/local/opt/openssl@1.1/lib
else
	OPENSSL_INCLUDE_PATH = 
	OPENSSL_LIB_PATH = 
endif
CAPSTONE_INCLUDE_PATH = 
CAPSTONE_LIB_PATH = 
KEYSTONE_INCLUDE_PATH = 
KEYSTONE_LIB_PATH = 
RAPIDJSON_INCLUDE_PATH = 

OUTPUT_DIR = ./bin/
COMMON_DIR = ./common/
PATCHER_DIR = ./navicat-patcher/
KEYGEN_DIR = ./navicat-keygen/

COMMON_HEADER = \
$(COMMON_DIR)Exception.hpp \
$(COMMON_DIR)ExceptionGeneric.hpp \
$(COMMON_DIR)ExceptionOpenssl.hpp \
$(COMMON_DIR)ExceptionSystem.hpp \
$(COMMON_DIR)ResourceTraitsOpenssl.hpp \
$(COMMON_DIR)ResourceWrapper.hpp \
$(COMMON_DIR)RSACipher.hpp

PATCHER_HEADER = \
$(PATCHER_DIR)CapstoneDisassembler.hpp \
$(PATCHER_DIR)KeystoneAssembler.hpp \
$(PATCHER_DIR)Elf64Interpreter.hpp \
$(PATCHER_DIR)ExceptionCapstone.hpp \
$(PATCHER_DIR)ExceptionKeystone.hpp \
$(PATCHER_DIR)MemoryAccess.hpp \
$(PATCHER_DIR)Misc.hpp \
$(PATCHER_DIR)PatchSolutions.hpp \
$(PATCHER_DIR)ResourceTraitsCapstone.hpp \
$(PATCHER_DIR)ResourceTraitsKeystone.hpp \
$(PATCHER_DIR)ResourceTraitsUnix.hpp

PATCHER_SOURCE = \
$(PATCHER_DIR)CapstoneDisassembler.cpp \
$(PATCHER_DIR)KeystoneAssembler.cpp \
$(PATCHER_DIR)Elf64Interpreter.cpp \
$(PATCHER_DIR)Misc.cpp \
$(PATCHER_DIR)PatchSolution.cpp \
$(PATCHER_DIR)PatchSolution0.cpp \
$(PATCHER_DIR)main.cpp

PATCHER_BINARY = $(OUTPUT_DIR)navicat-patcher

KEYGEN_HEADER = \
$(KEYGEN_DIR)Base32.hpp \
$(KEYGEN_DIR)Base64.hpp \
$(KEYGEN_DIR)SerialNumberGenerator.hpp

KEYGEN_SOURCE = \
$(KEYGEN_DIR)CollectInformation.cpp \
$(KEYGEN_DIR)GenerateLicense.cpp \
$(KEYGEN_DIR)main.cpp \
$(KEYGEN_DIR)SerialNumberGenerator.cpp

KEYGEN_BINARY = $(OUTPUT_DIR)navicat-keygen

patcher: $(PATCHER_HEADER) $(PATCHER_SOURCE)
	@if [ ! -d $(OUTPUT_DIR) ]; then mkdir -p $(OUTPUT_DIR); fi
	$(CC) -std=c++17 -O2 \
-I$(COMMON_DIR) \
$(if $(OPENSSL_INCLUDE_PATH),-I$(OPENSSL_INCLUDE_PATH),) $(if $(OPENSSL_LIB_PATH),-L$(OPENSSL_LIB_PATH),) \
$(if $(CAPSTONE_INCLUDE_PATH),-I$(CAPSTONE_INCLUDE_PATH),) $(if $(CAPSTONE_LIB_PATH),-L$(CAPSTONE_LIB_PATH),) \
$(if $(KEYSTONE_INCLUDE_PATH),-I$(KEYSTONE_INCLUDE_PATH),) $(if $(KEYSTONE_LIB_PATH),-L$(KEYSTONE_LIB_PATH),) \
$(PATCHER_SOURCE) -o $(PATCHER_BINARY) -lcrypto -lcapstone -lkeystone -lstdc++fs
	@echo

keygen: $(KEYGEM_HEADER) $(KEYGEN_SOURCE)
	@if [ ! -d $(OUTPUT_DIR) ]; then mkdir -p $(OUTPUT_DIR); fi
	$(CC) -std=c++17 -O2 \
-I$(COMMON_DIR) \
$(if $(OPENSSL_INCLUDE_PATH),-I$(OPENSSL_INCLUDE_PATH),) $(if $(OPENSSL_LIB_PATH),-L$(OPENSSL_LIB_PATH),) \
$(if $(RAPIDJSON_INCLUDE_PATH),-I$(RAPIDJSON_INCLUDE_PATH),) \
$(KEYGEN_SOURCE) -o $(KEYGEN_BINARY) -lcrypto

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

