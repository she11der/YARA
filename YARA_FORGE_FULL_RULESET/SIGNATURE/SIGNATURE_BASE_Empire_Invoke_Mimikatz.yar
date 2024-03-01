rule SIGNATURE_BASE_Empire_Invoke_Mimikatz : FILE
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Mimikatz.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "f7d6c1c4-2a24-54fd-b745-32d7894affc8"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "https://github.com/PowerShellEmpire/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_empire.yar#L100-L116"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c5481864b757837ecbc75997fa24978ffde3672b8a144a55478ba9a864a19466"
		logic_hash = "3e16bed3dd7b36920cdf01507f35e38d004e3ce2f3301911a8ee4aedbae6c5c3"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwc" ascii
		$s2 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)" fullword ascii
		$s3 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii

	condition:
		filesize <2500KB and 2 of them
}
