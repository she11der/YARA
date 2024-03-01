rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Diba_Target_2000 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "c6ae85b6-0670-558c-9ce5-64bd5822f35b"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2273-L2290"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "dfcd7d928c921dbe7162712ca74a105a938fd9ac675faaaa228d05139b2077de"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f9ea8ff5985b94f635d03f3aab9ad4fb4e8c2ad931137dba4f8ee8a809421b91"

	strings:
		$s1 = "0M1U1Z1p1" fullword ascii
		$op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
		$op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
		$op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 3 of them )
}
