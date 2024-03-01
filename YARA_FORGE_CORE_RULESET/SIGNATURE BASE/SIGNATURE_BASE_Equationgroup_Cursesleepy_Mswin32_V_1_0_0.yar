rule SIGNATURE_BASE_Equationgroup_Cursesleepy_Mswin32_V_1_0_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "f60ff218-1cb7-5f44-a756-1ee67649e6a6"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1067-L1082"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0dcbf2b314ff9c392ae0cb4f14762dd20c6b85f7f547af683db3aea1c57dee57"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6293439b4b49e94f923c76e302f5fc437023c91e063e67877d22333f05a24352"

	strings:
		$s1 = "A}%j,R" fullword ascii
		$op1 = { a1 e0 43 41 00 8b 0d 34 44 41 00 6b c0 }
		$op2 = { 33 C0 F3 A6 74 14 8B 5D 08 8B 4B 34 50 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}
