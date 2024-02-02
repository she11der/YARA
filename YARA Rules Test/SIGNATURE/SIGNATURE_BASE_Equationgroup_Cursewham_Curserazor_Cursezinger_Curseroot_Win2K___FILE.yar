rule SIGNATURE_BASE_Equationgroup_Cursewham_Curserazor_Cursezinger_Curseroot_Win2K___FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "6a877998-7021-54cb-b068-452d005955b6"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1342-L1362"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "a5a8e6a516b51c2eed616c80a1162990c1dda4460ec7786793d66820ca15b5a4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "aff27115ac705859871ab1bf14137322d1722f63705d6aeada43d18966843225"
		hash2 = "7a25e26950bac51ca8d37cec945eb9c38a55fa9a53bc96da53b74378fb10b67e"

	strings:
		$s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
		$s3 = ",%02d%03d" fullword ascii
		$s4 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
		$op1 = { 7d ec 8d 74 3f 01 0f af f7 c1 c6 05 }
		$op2 = { 29 f1 89 fb d3 eb 89 f1 d3 e7 }
		$op3 = { 7d e4 8d 5c 3f 01 0f af df c1 c3 05 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 3 of them )
}