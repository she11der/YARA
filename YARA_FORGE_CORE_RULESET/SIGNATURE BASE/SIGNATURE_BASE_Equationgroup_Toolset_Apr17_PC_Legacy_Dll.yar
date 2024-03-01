rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_PC_Legacy_Dll : HIGHVOL FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "254ff1f7-52ee-57fa-be02-2904e132e25c"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3129-L3144"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "923a595737bc83fe05d0ca7301c70e1cb03cecf97dfa99f5967b77b892a9a533"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0cbc5cc2e24f25cb645fb57d6088bcfb893f9eb9f27f8851503a1b33378ff22d"

	strings:
		$op1 = { 45 f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 }
		$op2 = { 49 c6 45 e1 73 c6 45 e2 57 c6 45 e3 }
		$op3 = { 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 6f c6 45 ea }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
