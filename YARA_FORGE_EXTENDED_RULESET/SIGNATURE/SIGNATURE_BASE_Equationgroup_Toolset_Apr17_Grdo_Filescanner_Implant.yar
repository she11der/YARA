rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Grdo_Filescanner_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "79a3cc02-0cda-59e2-8698-29a6cb0a3061"
		date = "2017-04-15"
		modified = "2023-01-06"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L2670-L2686"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ae88d27f41dd4888c445c654c919b3862fe3fc8c92aef816b22b2fb408a49cce"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8d2e43567e1360714c4271b75c21a940f6b26a789aa0fce30c6478ae4ac587e4"

	strings:
		$s1 = "system32\\winsrv.dll" fullword wide
		$s2 = "raw_open CreateFile error" fullword ascii
		$s3 = "\\dllcache\\" wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and all of them )
}
