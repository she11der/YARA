rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Msgks_Mskgu___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "1692848d-a8db-5c11-9dc4-f1b0c45a78c3"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2688-L2704"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "d3a230d29997ab247db2b7a2a0f369206513a98c16f744e2fb1fca6495d5e36b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7b4986aee8f5c4dca255431902907b36408f528f6c0f7d7fa21f079fa0a42e09"
		hash2 = "ef906b8a8ad9dca7407e0a467b32d7f7cf32814210964be2bfb5b0e6d2ca1998"

	strings:
		$op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
		$op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
		$op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}