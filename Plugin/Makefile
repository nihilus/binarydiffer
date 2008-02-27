PROC=DarunGrim2
IDA=C:\mat\Bin\IDASDK\5.0\\
SNIPPET_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Snippets
IPC_DIR=\mat\Projects\ResearchTools\DevEnv\Library\IPC
IDA_LIB_DIR=..\..\Lib
DIFF_ENGINE_DIR=..\DiffEngine
CRYPTO_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Crypto
FILE_DIR=\mat\Projects\ResearchTools\DevEnv\Library\File
DATABASE_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Database
SOCKET_LIB_DIR=\mat\Projects\ResearchTools\DevEnv\Library\Socket

CPP=cl.exe
CPP_PROJ=/nologo /Gz /D "WIN32" /D "_USE_IDA_SDK_49_OR_UPPER" /D "_USRDLL" /D "__NT__" /D "__IDP__" /D MAXSTR=1024 /Fo$(F) /c  /EHsc -D_MT /WX  -I$(CRYPTO_DIR) -I"$(I)" -I$(IPC_DIR) -I$(SNIPPET_DIR) -I$(IDACODE_DIR) -I..\AnalyzerConsole -I. -I$(IDA_LIB_DIR) -I$(DIFF_ENGINE_DIR) -I$(FILE_DIR) -I$(DATABASE_DIR) -I$(SOCKET_LIB_DIR) /V0.1 -MTd /Zi -DINTERNAL_SERVER 

LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib user32.lib advapi32.lib version.lib $(DATABASE_DIR)\sqlite3.lib "$(IDALIB)" $(LIBS) /nologo /dll /out:"$(BINARY)" /implib:$(F)$(PROC)$(A) /libpath:"$(L)" /export:PLUGIN /VERSION:0.1 /debug

I=$(IDA)include\\
L=$(IDA)libvc.w32\                   # libraries directory
R=bin\                         # results directory
F=.\vc.w32\                          # object files directory
SUBDIR=
PLUGIN=.plw                          # PLUGIN extension
O=.obj                               # object file extension
A=.lib                               # library file extension
RM=erase /q                          # File Remover
IDALIB=$(L)ida$(A)

OBJS=$(F)$(PROC)$(O) $(F)IDAAnalysis$(O) $(F)AnalysisServer$(O) $(F)fileinfo$(O) $(F)md5$(O) $(F)SharedMemory$(O) $(F)SharedSocket$(O) $(F)SocketOperation.obj

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

$(F)AnalysisServer.obj: $(DIFF_ENGINE_DIR)\AnalysisServer.cpp
    $(CPP) $(CPP_PROJ) $(DIFF_ENGINE_DIR)\AnalysisServer.cpp

$(F)SharedMemory.obj: $(IPC_DIR)\SharedMemory.cpp
    $(CPP) $(CPP_PROJ) $(IPC_DIR)\SharedMemory.cpp

$(F)SharedSocket.obj: $(IPC_DIR)\SharedSocket.cpp
    $(CPP) $(CPP_PROJ) $(IPC_DIR)\SharedSocket.cpp
   
$(F)md5$(O): $(CRYPTO_DIR)\md5.cpp
    $(CPP) $(CPP_PROJ) $(CRYPTO_DIR)\md5.cpp

$(F)fileinfo$(O): $(FILE_DIR)\fileinfo.cpp
    $(CPP) $(CPP_PROJ) $(FILE_DIR)\fileinfo.cpp
    
$(F)IDAAnalysis$(O): $(IDA_LIB_DIR)\IDAAnalysis.cpp
    $(CPP) $(CPP_PROJ) $(IDA_LIB_DIR)\IDAAnalysis.cpp    

$(F)SocketOperation.obj: $(SOCKET_LIB_DIR)\SocketOperation.cpp
    $(CPP) $(CPP_PROJ) $(SOCKET_LIB_DIR)\SocketOperation.cpp  

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
