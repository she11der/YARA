rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Diba_Target_BH_2000 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "b02fa407-e6f1-5c2d-a587-7edb55dbe0a5"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3011-L3025"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0cd3ba351b1c5716ed322c9f177a848322324526f3d39c2be5cc34bc6aee9fa6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0654b4b8727488769390cd091029f08245d690dd90d1120e8feec336d1f9e788"

	strings:
		$s2 = "0M1U1Z1p1" fullword ascii
		$s14 = "SPRQWV" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
