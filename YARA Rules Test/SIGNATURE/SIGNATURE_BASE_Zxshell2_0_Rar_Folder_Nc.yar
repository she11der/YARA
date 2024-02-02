rule SIGNATURE_BASE_Zxshell2_0_Rar_Folder_Nc
{
	meta:
		description = "Webshells Auto-generated - file nc.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "106209fc-f957-5131-825b-8eb7835625e0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8902-L8916"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "2cd1bf15ae84c5f6917ddb128827ae8b"
		logic_hash = "6106758aedb33f8983f387a58fcd815c47f793cd2a7ea3b0ebed13dd1d5b6e83"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "WSOCK32.dll"
		$s1 = "?bSUNKNOWNV"
		$s7 = "p@gram Jm6h)"
		$s8 = "ser32.dllCONFP@"

	condition:
		all of them
}