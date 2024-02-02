rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Sendpktrigger___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "6cbf95eb-323c-53a3-9aca-222626add4dc"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2884-L2897"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "277367e69406a84ff4ff6b57d05bf97468b0083e23f9c5cd14cdd26cad5846d7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"

	strings:
		$x1 = "----====**** PORT KNOCK TRIGGER BEGIN ****====----" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}