rule SIGNATURE_BASE_Foudre_Backdoor_SFX___FILE
{
	meta:
		description = "Detects Foudre Backdoor SFX"
		author = "Florian Roth (Nextron Systems)"
		id = "b5c7cd6b-48c8-5703-b695-19d226de1810"
		date = "2017-08-01"
		modified = "2023-12-05"
		reference = "https://goo.gl/Nbqbt6"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_foudre.yar#L77-L93"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "dd5492f5314cb87fdb7c8b29bdf31e1fcd8541ed47b20f309538437d9c6ac600"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2b37ce9e31625d8b9e51b88418d4bf38ed28c77d98ca59a09daab01be36d405a"
		hash2 = "4d51a0ea4ecc62456295873ff135e4d94d5899c4de749621bafcedbf4417c472"

	strings:
		$s1 = "main.exe" fullword ascii
		$s2 = "pub.key" fullword ascii
		$s3 = "WinRAR self-extracting archive" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}