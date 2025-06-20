add_executable(ExeInfo winmain.cpp exeinfo.cpp messagebox.cpp resource.rc $<$<CXX_COMPILER_ID:MSVC>:exeinfo.manifest>)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS")
set_property(TARGET ExeInfo PROPERTY VS_DPI_AWARE "ON")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
