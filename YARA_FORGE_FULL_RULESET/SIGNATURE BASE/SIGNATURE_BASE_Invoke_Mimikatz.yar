rule SIGNATURE_BASE_Invoke_Mimikatz
{
	meta:
		description = "Detects Invoke-Mimikatz String"
		author = "Florian Roth (Nextron Systems)"
		id = "37de51a6-e1bb-5ee7-9b7f-8fe17b3697b5"
		date = "2016-08-03"
		modified = "2023-12-05"
		reference = "https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_invoke_mimikatz.yar#L10-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b9bfa54a64d6f6b8af97ec62c9102ccf0912a19b65fbd25a4836480e63497a00"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f1a499c23305684b9b1310760b19885a472374a286e2f371596ab66b77f6ab67"

	strings:
		$x2 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm" ascii
		$x3 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii

	condition:
		1 of them
}
