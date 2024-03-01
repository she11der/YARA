rule SIGNATURE_BASE_Equationgroup_Cursehappy_Win2K_V_6_1_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "7b75d4aa-2cbc-57fc-8fda-015bbc1fb25e"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1401-L1415"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "3bf5878c3be20a7a543d4937c6d820df726062e39ee262a6c31f7e91b32fd55e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "eb669afd246a7ac4de79724abcce5bda38117b3138908b90cac58936520ea632"

	strings:
		$op1 = { e8 24 2c 01 00 85 c0 89 c6 ba ff ff ff ff 74 d6 }
		$op2 = { 89 4c 24 04 89 34 24 89 44 24 08 e8 ce 49 ff ff }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and all of them )
}
