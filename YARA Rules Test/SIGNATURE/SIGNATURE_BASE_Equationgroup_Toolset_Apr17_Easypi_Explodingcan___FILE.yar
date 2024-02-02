rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Easypi_Explodingcan___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "53d4ebf1-cce3-5fc8-8304-064b4113c9d7"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1731-L1747"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "c5978d8cbffde2339cadd84f44d1df24e76f298a2f05bd9a6565246bfae1b1e3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "dc1ddad7e8801b5e37748ec40531a105ba359654ffe8bdb069bd29fb0b5afd94"
		hash2 = "97af543cf1fb59d21ba5ec6cb2f88c8c79c835f19c8f659057d2f58c321a0ad4"

	strings:
		$x1 = "[-] %s - Target might not be in a usable state." fullword ascii
		$x2 = "[*] Exploiting Target" fullword ascii
		$x3 = "[-] Encoding Exploit Payload failed!" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}