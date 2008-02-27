# Nmake macros for building Windows 32-Bit apps

!include <Win32.Mak>

PROCESS_UTIL_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Snippets
IPC_DIR=\mat\Projects\ResearchTools\DevEnv\Library\IPC
IDA_LIB_DIR=..\Lib
SOCKET_LIB_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Socket

cflags=$(cflags) -I$(IPC_DIR) -I.. -I$(PROCESS_UTIL_DIR) -I$(IDA_LIB_DIR) -I$(SOCKET_LIB_DIR) /Zi /EHsc -DSTANDALONE_SERVER 
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

$(OUTDIR)\SharedMemory.obj: $(IPC_DIR)\SharedMemory.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(IPC_DIR)\SharedMemory.cpp

$(OUTDIR)\SharedSocket.obj: $(IPC_DIR)\SharedSocket.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(IPC_DIR)\SharedSocket.cpp

$(OUTDIR)\ProcessUtils.obj: $(PROCESS_UTIL_DIR)\ProcessUtils.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(PROCESS_UTIL_DIR)\ProcessUtils.cpp

$(OUTDIR)\SocketOperation.obj: $(SOCKET_LIB_DIR)\SocketOperation.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(SOCKET_LIB_DIR)\SocketOperation.cpp

$(OUTDIR)\client.exe: $(OUTDIR)\client.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj
    $(link) $(conflags) -out:$(OUTDIR)\client.exe $(OUTDIR)\client.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(conlibs)

#--------------------- Clean Rule --------------------------------------------------------
# Rules for cleaning out those old files
clean:
        $(CLEANUP)
