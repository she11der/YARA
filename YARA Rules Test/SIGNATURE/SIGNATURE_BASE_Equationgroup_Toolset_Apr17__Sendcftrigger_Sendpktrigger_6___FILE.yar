rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__Sendcftrigger_Sendpktrigger_6___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "658d6f7d-2164-5e43-b5a5-d9bea9cd2e27"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3363-L3379"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "4fb290bdf15e0701b6d543e1f978011046abe23e58c790ee1b992a5e0443a271"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "3bee31b9edca8aa010a4684c2806b0ca988b2bcc14ad0964fec4f11f3f6fb748"
		hash2 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"

	strings:
		$s4 = "* Failed to connect to destination - %u" fullword wide
		$s6 = "* Failed to convert destination address into sockaddr_storage values" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 1 of them )
}