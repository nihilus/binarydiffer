# Nmake macros for building Windows 32-Bit apps

!include <Win32.Mak>

LIB_DIR=..\Lib

cflags=$(cflags) -I.. /Zi /EHsc /D "_CRT_SECURE_NO_DEPRECATE" /D "USE_DANGEROUS_FUNCTIONS" -DSTANDALONE_SERVER -I$(LIB_DIR)
conflags=$(conflags) /DEBUG
conlibs=$(conlibs) user32.lib

all: $(OUTDIR) $(OUTDIR)\BinaryDiffer.exe 
#$(OUTDIR)\client.exe

#----- If OUTDIR does not exist, then create directory
$(OUTDIR) :
    if not exist "$(OUTDIR)/$(NULL)" mkdir $(OUTDIR)

$(OUTDIR)\main.obj: main.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" main.cpp

$(OUTDIR)\BinaryDiffer.exe: $(OUTDIR)\main.obj $(OUTDIR)\AnalysisServer.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj
    $(link) $(conflags) -out:$(OUTDIR)\BinaryDiffer.exe $(OUTDIR)\main.obj $(OUTDIR)\AnalysisServer.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(OUTDIR)\ProcessUtils.obj $(OUTDIR)\SocketOperation.obj $(conlibs)

$(OUTDIR)\AnalysisServer.obj: AnalysisServer.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" AnalysisServer.cpp

$(OUTDIR)\client.obj: client.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" client.cpp

$(OUTDIR)\SharedMemory.obj: $(LIB_DIR)\SharedMemory.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\SharedMemory.cpp

$(OUTDIR)\SharedSocket.obj: $(LIB_DIR)\SharedSocket.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\SharedSocket.cpp

$(OUTDIR)\ProcessUtils.obj: $(LIB_DIR)\ProcessUtils.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\ProcessUtils.cpp

$(OUTDIR)\SocketOperation.obj: $(LIB_DIR)\SocketOperation.cpp
    $(cc) $(cflags) $(cvars) /WX /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" $(LIB_DIR)\SocketOperation.cpp

$(OUTDIR)\client.exe: $(OUTDIR)\client.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj
    $(link) $(conflags) -out:$(OUTDIR)\client.exe $(OUTDIR)\client.obj $(OUTDIR)\SharedMemory.obj $(OUTDIR)\SharedSocket.obj $(conlibs)

#--------------------- Clean Rule --------------------------------------------------------
# Rules for cleaning out those old files
clean:
        $(CLEANUP)
