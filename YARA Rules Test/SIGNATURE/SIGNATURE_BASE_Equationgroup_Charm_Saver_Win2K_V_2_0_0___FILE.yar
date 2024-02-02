rule SIGNATURE_BASE_Equationgroup_Charm_Saver_Win2K_V_2_0_0___FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "9c2e3b70-ffa2-598a-9f99-f7a574b06c14"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1383-L1399"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "87cea1f46a3165485274165e840a4945d6f6a6f9ff7fd011e685e8bb90acae8a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0f7936a37482532a8ba5df4112643ed7579dd0e59181bfca9c641b9ba0a9912f"

	strings:
		$s2 = "0123456789abcdefABCEDF:" fullword ascii
		$op0 = { b8 ff ff ff ff 7f 65 eb 30 8b 55 0c 89 d7 0f b6 }
		$op2 = { ba ff ff ff ff 83 c4 6c 89 d0 5b 5e 5f 5d c3 90 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and all of them )
}