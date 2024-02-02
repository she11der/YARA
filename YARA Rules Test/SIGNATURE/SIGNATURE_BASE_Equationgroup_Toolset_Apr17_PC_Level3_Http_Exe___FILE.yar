rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_PC_Level3_Http_Exe___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "9bb4224e-f900-5f5c-8091-088a4b791ada"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3077-L3094"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "50d83b157c338830eea6aba2e09e9d513dd5b50e257d1a16c0d51616bfa26a7f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3e855fbea28e012cd19b31f9d76a73a2df0eb03ba1cb5d22aafe9865150b020c"

	strings:
		$s1 = "Copyright (C) Microsoft" fullword wide
		$op1 = { 24 39 65 c6 44 24 3a 6c c6 44 24 3b 65 c6 44 24 }
		$op2 = { 44 24 4e 41 88 5c 24 4f ff }
		$op3 = { 44 24 3f 6e c6 44 24 40 45 c6 44 24 41 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and all of them )
}