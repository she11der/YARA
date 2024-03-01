rule SIGNATURE_BASE_Equationgroup_Curseyo_Win2K_V_1_0_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "8161907d-d6bd-58c5-806d-387321b93b21"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1289-L1306"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ad9bb848a0c4805a14465ff44e3c967c9afa7369536a211a8a1fb100902fbb55"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5dc77614764b23a38610fdd8abe5b2274222f206889e4b0974a3fea569055ed6"

	strings:
		$s1 = "0123456789abcdefABCEDF:" fullword ascii
		$op0 = { c6 06 5b 8b bd 70 ff ff ff 8b 9d 64 ff ff ff 0f }
		$op1 = { 55 b8 ff ff ff ff 89 e5 83 ec 28 89 7d fc 8b 7d }
		$op2 = { ff 05 10 64 41 00 89 34 24 e8 df 1e 00 00 e9 31 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
