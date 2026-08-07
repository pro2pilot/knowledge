Option Explicit

Dim shell, fso, scriptDir, psScript, command
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
psScript = fso.BuildPath(scriptDir, "tools\open-inspector.ps1")

If Not fso.FileExists(psScript) Then
  MsgBox "Missing launcher helper: " & psScript, vbCritical, ".knowledge Inspector"
  WScript.Quit 1
End If

shell.CurrentDirectory = scriptDir
command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & psScript & """ -KnowledgeRoot """ & scriptDir & """"
shell.Run command, 0, False
