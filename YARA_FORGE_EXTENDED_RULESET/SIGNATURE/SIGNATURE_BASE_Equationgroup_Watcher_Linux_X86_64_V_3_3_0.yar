rule SIGNATURE_BASE_Equationgroup_Watcher_Linux_X86_64_V_3_3_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "4077242e-a0f2-54a8-afad-f52b8ed874ba"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L1435-L1450"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "be2ca3791ef1025db6a1dd6bcdf1a9f0b224c3f7585af4546029840251c50094"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a8d65593f6296d6d06230bcede53b9152842f1eee56a2a72b0a88c4f463a09c3"

	strings:
		$s1 = "forceprismheader" fullword ascii
		$s2 = "invalid option `" fullword ascii
		$s3 = "forceprism" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <900KB and all of them )
}
