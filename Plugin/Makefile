PROC=BinaryDiffer
IDA=C:\mat\DevEnv\idasdk50
SNIPPET_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Snippets
IPC_DIR=\mat\Projects\ResearchTools\DevEnv\Library\IPC
IDA_LIB_DIR="\mat\Projects\ResearchTools\Binary\Static Analysis\IDALib"
CRYPTO_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Crypto
FILE_DIR=\mat\Projects\ResearchTools\DevEnv\Library\File
DATABASE_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Database
SOCKET_LIB_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Socket

LIB_DIR=..\Lib
DIFF_ENGINE_DIR=..\DiffEngine
CPP=cl.exe

# -DINTERNAL_SERVER: For testing internal server
CPP_PROJ=/nologo /Gz /D "WIN32" /D "_USE_IDA_SDK_49_OR_UPPER" /D "_USRDLL" /D "__NT__" /D "__IDP__" /D MAXSTR=1024 /Fo$(F) /c  /EHsc -D_MT /WX  -I"$(I)" -I..\AnalyzerConsole -I. /V0.1 -MTd /Zi -DEXTERNAL_SERVER="\"BinaryDiffer.exe\"" -I$(DIFF_ENGINE_DIR) -I$(LIB_DIR)

LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib user32.lib advapi32.lib version.lib "$(IDALIB)" $(LIBS) /nologo /dll /out:"$(BINARY)" /implib:$(F)$(PROC)$(A) /libpath:"$(L)" /export:PLUGIN /VERSION:0.1 /debug

I=$(IDA)\include\\
L=$(IDA)\libvc.w32\                   # libraries directory
R=bin\                         # results directory
F=.\vc.w32\                          # object files directory
SUBDIR=
PLUGIN=.plw                          # PLUGIN extension
O=.obj                               # object file extension
A=.lib                               # library file extension
RM=erase /q                          # File Remover
IDALIB=$(L)ida$(A)

OBJS=$(F)IDAAnalysis$(O) $(F)AnalysisServer$(O) $(F)fileinfo$(O) $(F)md5$(O) $(F)SharedMemory$(O) $(F)SharedSocket$(O) $(F)SocketOperation.obj $(F)ProcessUtils$(O) $(F)$(PROC)$(O)

BINARY=$(R)$(SUBDIR)$(PROC)$(PLUGIN)

all: $(R)$(SUBDIR) $(F) "$(BINARY)"

clean:
	-@$(RM) $(F)*$(O)
	-@$(RM) $(F)*$(A)
	-@$(RM) $(F)*.exp
	-@$(RM) "$(BINARY)"

distclean: clean
	-@$(RM) $(F)*
	rmdir $(F)

$(F):
	if not exist $(F) mkdir $(F)

$(R)$(SUBDIR):
	if not exist $(R)$(SUBDIR) mkdir $(R)$(SUBDIR)

.c{$(F)}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $< 
<<

$(LIB_DIR)\AnalysisServer.h:
	copy $(DIFF_ENGINE_DIR)\AnalysisServer.h $(LIB_DIR)
$(LIB_DIR)\AnalysisServer.cpp: $(LIB_DIR)\AnalysisServer.h $(LIB_DIR)\SocketOperation.h $(LIB_DIR)\SharedSocket.h $(LIB_DIR)\IDAAnalysisCommon.h
	copy $(DIFF_ENGINE_DIR)\AnalysisServer.cpp $(LIB_DIR)

$(LIB_DIR)\TLV.h:
	copy $(IPC_DIR)\TLV.h $(LIB_DIR)

$(LIB_DIR)\SharedMemory.h: $(LIB_DIR)\TLV.h
	copy $(IPC_DIR)\SharedMemory.h $(LIB_DIR)
$(LIB_DIR)\SharedMemory.cpp: $(LIB_DIR)\SharedMemory.h
	copy $(IPC_DIR)\SharedMemory.cpp $(LIB_DIR)

$(LIB_DIR)\SharedSocket.h:
	copy $(IPC_DIR)\SharedSocket.h $(LIB_DIR)
$(LIB_DIR)\SharedSocket.cpp: $(LIB_DIR)\SharedSocket.h
	copy $(IPC_DIR)\SharedSocket.cpp $(LIB_DIR)

$(LIB_DIR)\md5.h:
	copy $(CRYPTO_DIR)\md5.h $(LIB_DIR)
$(LIB_DIR)\md5.cpp: $(LIB_DIR)\md5.h
	copy $(CRYPTO_DIR)\md5.cpp $(LIB_DIR)

$(LIB_DIR)\fileinfo.h:
	copy $(FILE_DIR)\fileinfo.h $(LIB_DIR)
$(LIB_DIR)\fileinfo.cpp: $(LIB_DIR)\fileinfo.h $(LIB_DIR)\md5.cpp
	copy $(FILE_DIR)\fileinfo.cpp $(LIB_DIR)

$(LIB_DIR)\IdaIncludes.h:
	copy $(IDA_LIB_DIR)\IdaIncludes.h $(LIB_DIR)
$(LIB_DIR)\IDAAnalysisCommon.h:	
	copy $(IDA_LIB_DIR)\IDAAnalysisCommon.h $(LIB_DIR)
$(LIB_DIR)\IDAAnalysis.h: $(LIB_DIR)\IdaIncludes.h $(LIB_DIR)\SharedMemory.h
	copy $(IDA_LIB_DIR)\IDAAnalysis.h $(LIB_DIR)
$(LIB_DIR)\IDAAnalysis.cpp: $(LIB_DIR)\IDAAnalysis.h $(LIB_DIR)\IDAAnalysisCommon.h
	copy $(IDA_LIB_DIR)\IDAAnalysis.cpp $(LIB_DIR)

$(LIB_DIR)\SocketOperation.h:	
	copy $(SOCKET_LIB_DIR)\SocketOperation.h $(LIB_DIR)
$(LIB_DIR)\SocketOperation.cpp:	$(LIB_DIR)\SocketOperation.h
	copy $(SOCKET_LIB_DIR)\SocketOperation.cpp $(LIB_DIR)

$(F)AnalysisServer.obj: $(LIB_DIR)\AnalysisServer.cpp
    $(CPP) $(CPP_PROJ) $(LIB_DIR)\AnalysisServer.cpp

$(F)SharedMemory.obj: $(LIB_DIR)\SharedMemory.cpp
    $(CPP) $(CPP_PROJ) $(LIB_DIR)\SharedMemory.cpp

$(F)SharedSocket.obj: $(LIB_DIR)\SharedSocket.cpp
    $(CPP) $(CPP_PROJ) $(LIB_DIR)\SharedSocket.cpp
   
$(F)md5$(O): $(CRYPTO_DIR)\md5.cpp
    $(CPP) $(CPP_PROJ) $(LIB_DIR)\md5.cpp

$(F)fileinfo$(O): $(LIB_DIR)\fileinfo.cpp
    $(CPP) $(CPP_PROJ) $(LIB_DIR)\fileinfo.cpp
    
$(F)IDAAnalysis$(O): $(LIB_DIR)\IDAAnalysis.cpp
    $(CPP) $(CPP_PROJ) $(LIB_DIR)\IDAAnalysis.cpp    

$(F)SocketOperation.obj: $(LIB_DIR)\SocketOperation.cpp
    $(CPP) $(CPP_PROJ) $(LIB_DIR)\SocketOperation.cpp  

$(LIB_DIR)\ProcessUtils.h:	
	copy $(SNIPPET_DIR)\ProcessUtils.h $(LIB_DIR)
$(LIB_DIR)\ProcessUtils.cpp:	$(LIB_DIR)\ProcessUtils.h
	copy $(SNIPPET_DIR)\ProcessUtils.cpp $(LIB_DIR)
$(F)ProcessUtils.obj: $(LIB_DIR)\ProcessUtils.cpp
    $(CPP) $(CPP_PROJ) $(LIB_DIR)\ProcessUtils.cpp

.cpp{$(F)}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $< 
<<

.cpp{}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $< 
<<

"$(BINARY)" : $(F) $(OBJS)
	$(LINK32) @<<
  $(LINK32_FLAGS) $(OBJS) 
<<
