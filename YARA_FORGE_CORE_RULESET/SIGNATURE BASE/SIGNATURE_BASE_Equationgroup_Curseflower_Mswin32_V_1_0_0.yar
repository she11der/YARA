rule SIGNATURE_BASE_Equationgroup_Curseflower_Mswin32_V_1_0_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "4138f87a-4584-5efc-a168-633838893e2f"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1138-L1153"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e70954945b3a5e08e5ae216b16702056b403dbf14391276eae1ed13e8273c1ee"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fdc452629ff7befe02adea3a135c3744d8585af890a4301b2a10a817e48c5cbf"

	strings:
		$s1 = "<pVt,<et(<st$<ct$<nt" fullword ascii
		$op1 = { 6a 04 83 c0 08 6a 01 50 e8 10 34 00 00 83 c4 10 }

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
