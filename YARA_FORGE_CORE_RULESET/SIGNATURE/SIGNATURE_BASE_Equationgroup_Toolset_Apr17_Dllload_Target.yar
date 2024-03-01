rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Dllload_Target : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "9def0814-c86a-5fae-abc2-4185596a74aa"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2292-L2309"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "ab50ad9e01c55b3f40e98e6e2cf77c1ad7d6d6ec81a56bbb2263a6e05912e272"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a42d5201af655e43cefef30d7511697e6faa2469dc4a74bc10aa060b522a1cf5"

	strings:
		$s1 = "BzWKJD+" fullword ascii
		$op1 = { 44 24 6c 6c 88 5c 24 6d }
		$op2 = { 44 24 54 63 c6 44 24 55 74 c6 44 24 56 69 }
		$op3 = { 44 24 5c 6c c6 44 24 5d 65 c6 44 24 5e }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
