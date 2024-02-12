rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Architouch_1_0_0___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "c5af05b5-9dfa-535f-b9ea-c82ef79bae7e"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1538-L1551"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "cb6959b7b50e6f2895bab5f3355bef836c9a9774285cfb5fea339ce3d2c67f73"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"

	strings:
		$s1 = "[+] Target is %s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}