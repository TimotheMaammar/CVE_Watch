' Launches run_6h.bat with its console window hidden (style 0). Task Scheduler
' is pointed at this .vbs (via wscript.exe) instead of the .bat directly,
' which is what was popping up a cmd window on every run.
Set objShell = CreateObject("WScript.Shell")
objShell.Run """" & CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName) & "\run_6h.bat""", 0, False
