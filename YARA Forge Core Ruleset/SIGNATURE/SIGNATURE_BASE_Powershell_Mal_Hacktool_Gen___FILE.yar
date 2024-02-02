rule SIGNATURE_BASE_Powershell_Mal_Hacktool_Gen___FILE
{
	meta:
		description = "Detects PowerShell hack tool samples - generic PE loader"
		author = "Florian Roth (Nextron Systems)"
		id = "d1fc4594-d816-5d02-bff6-3f220477b555"
		date = "2017-11-02"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L4088-L4104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "273222cde3ff155cef09c25192dcb4865179e8172e625fe8f43b21a13fe1a170"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d442304ca839d75b34e30e49a8b9437b5ab60b74d85ba9005642632ce7038b32"

	strings:
		$x1 = "$PEBytes32 = 'TVqQAAMAAAAEAAAA" wide
		$x2 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword wide
		$x3 = "@($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword wide
		$x4 = "(Shellcode: LoadLibraryA.asm)" fullword wide

	condition:
		filesize <8000KB and 1 of them
}