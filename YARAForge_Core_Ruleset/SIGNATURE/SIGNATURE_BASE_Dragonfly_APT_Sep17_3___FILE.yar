rule SIGNATURE_BASE_Dragonfly_APT_Sep17_3___FILE
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		author = "Florian Roth (Nextron Systems)"
		id = "4eafd732-80bc-5f50-bf0d-096df4d35d61"
		date = "2017-09-12"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_dragonfly.yar#L68-L89"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "f564685eb1426d1a3eb888a888bfdf3a8fa9bc96af07fb0bc5f10c0a324f1d9d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b051a5997267a5d7fa8316005124f3506574807ab2b25b037086e2e971564291"

	strings:
		$s1 = "kernel64.dll" fullword ascii
		$s2 = "ws2_32.dQH" fullword ascii
		$s3 = "HGFEDCBADCBA" fullword ascii
		$s4 = "AWAVAUATWVSU" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and (pe.imphash()=="6f03fb864ff388bac8680ac5303584be" or all of them ))
}