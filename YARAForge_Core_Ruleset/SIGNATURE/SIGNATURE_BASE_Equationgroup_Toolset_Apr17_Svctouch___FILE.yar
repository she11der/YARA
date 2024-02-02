rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Svctouch___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "a1246afa-32ba-5730-91a2-b1116160d662"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3146-L3159"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0e876611ffe4740141a0454f68cfc7dd3c46e0fd44deeb9f3e0f66c8fccd3745"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "96b6a3c4f53f9e7047aa99fd949154745e05dc2fd2eb21ef6f0f9b95234d516b"

	strings:
		$s1 = "Causes: Firewall,Machine down,DCOM disabled\\not supported,etc." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <10KB and 1 of them )
}