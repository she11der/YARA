rule SIGNATURE_BASE_Equationgroup_Cursetingle_2_0_1_2_Mswin32_V_2_0_1 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "7a1870ba-d600-5c11-8d3d-41395ad8be63"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L1051-L1065"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "bc27edc946beb5065d4fe43e53a33b448c24c7dd3eae0cedd4770c02fce7836b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "614bf159b956f20d66cedf25af7503b41e91841c75707af0cdf4495084092a61"

	strings:
		$s1 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
		$s2 = "0123456789abcdefABCEDF:" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
