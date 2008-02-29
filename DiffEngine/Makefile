# Nmake macros for building Windows 32-Bit apps

!include <Win32.Mak>

PROCESS_UTIL_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Snippets
IPC_DIR=\mat\Projects\ResearchTools\DevEnv\Library\IPC
LIB_DIR=..\Lib
SOCKET_LIB_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Socket

cflags=$(cflags) -I.. /Zi /EHsc -DSTANDALONE_SERVER 
conflags=$(conflags) /DEBUG
conlibs=$(conlibs) user32.lib

all: $(OUTDIR) $(OUTDIR)\DarunGrim2.exe 
#$(OUTDIR)\client.exe

#----- If OUTDIR does not exist, then create directory
$(OUTDIR) :
    if not exist "$(OUTDIR)/$(NULL)" mkdir $(OUTDIR)

$(OUTDIR)\main.obj: main.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" main.cpp

$(OUTDIR)\DarunGrim2.exe: $(OUTDIR)\main.obj $(OUTDIR)\AnalysisServer.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj
    $(link) $(conflags) -out:$(OUTDIR)\DarunGrim2.exe $(OUTDIR)\main.obj $(OUTDIR)\AnalysisServer.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(conlibs)

$(OUTDIR)\AnalysisServer.obj: AnalysisServer.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" AnalysisServer.cpp

$(OUTDIR)\client.obj: client.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" client.cpp

$(LIB_DIR)\SharedMemory.h: $(LIB_DIR)\TLV.h
	copy $(IPC_DIR)\SharedMemory.h $(LIB_DIR)
$(LIB_DIR)\SharedMemory.cpp: $(LIB_DIR)\SharedMemory.h
	copy $(IPC_DIR)\SharedMemory.cpp $(LIB_DIR)

$(LIB_DIR)\SharedSocket.h:
	copy $(IPC_DIR)\SharedSocket.h $(LIB_DIR)
$(LIB_DIR)\SharedSocket.cpp: $(LIB_DIR)\SharedSocket.h
	copy $(IPC_DIR)\SharedSocket.cpp $(LIB_DIR)

$(OUTDIR)\SharedMemory.obj: $(IPC_DIR)\SharedMemory.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(IPC_DIR)\SharedMemory.cpp

$(OUTDIR)\SharedSocket.obj: $(IPC_DIR)\SharedSocket.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(IPC_DIR)\SharedSocket.cpp

$(LIB_DIR)\ProcessUtils.h:
	copy $(PROCESS_UTIL_DIR)\ProcessUtils.h $(LIB_DIR)
$(LIB_DIR)\ProcessUtils.cpp: $(LIB_DIR)\ProcessUtils.h
	copy $(PROCESS_UTIL_DIR)\ProcessUtils.cpp $(LIB_DIR)
	
$(OUTDIR)\ProcessUtils.obj: $(LIB_DIR)\ProcessUtils.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\ProcessUtils.cpp

$(LIB_DIR)\SocketOperation.h:	
	copy $(SOCKET_LIB_DIR)\SocketOperation.h $(LIB_DIR)
$(LIB_DIR)\SocketOperation.cpp:	$(LIB_DIR)\SocketOperation.h
	copy $(SOCKET_LIB_DIR)\SocketOperation.cpp $(LIB_DIR)

$(OUTDIR)\SocketOperation.obj: $(LIB_DIR)\SocketOperation.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\SocketOperation.cpp

$(OUTDIR)\client.exe: $(OUTDIR)\client.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj
    $(link) $(conflags) -out:$(OUTDIR)\client.exe $(OUTDIR)\client.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(conlibs)

#--------------------- Clean Rule --------------------------------------------------------
# Rules for cleaning out those old files
clean:
        $(CLEANUP)
