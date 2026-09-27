# Makefile for MinGW cross-compilation of AD Integrity Watchdog Agent
CXX = x86_64-w64-mingw32-g++
CXXFLAGS = -O2 -std=c++11 -Wall -static -static-libgcc -static-libstdc++
LDFLAGS = -mwindows -lnetapi32 -ladvapi32 -lwininet -lshlwapi

TARGET_ALPHA = agent_alpha.exe
TARGET_BRAVO = agent_bravo.exe
TARGET_UNIFIED = agent.exe
SRC = agent.cpp

.PHONY: all clean alpha bravo unified

all: $(TARGET_ALPHA) $(TARGET_BRAVO) $(TARGET_UNIFIED)

$(TARGET_ALPHA): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET_ALPHA) $(LDFLAGS)

$(TARGET_BRAVO): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET_BRAVO) $(LDFLAGS)

$(TARGET_UNIFIED): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET_UNIFIED) $(LDFLAGS)

clean:
	rm -f *.exe *.o
