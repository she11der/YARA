rule SIGNATURE_BASE_Equationgroup_Pclean_V2_1_1_2___FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file pclean.v2.1.1.0-linux-i386"
		author = "Florian Roth (Nextron Systems)"
		id = "1b31af01-8c30-513a-a615-82dcb940e06d"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L469-L483"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "9323ef0c76348d242b010cf0f1c6a1bf5dd120a02418350bb0ed137f468ac624"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"

	strings:
		$s3 = "** SIGNIFICANTLY IMPROVE PROCESSING TIME" fullword ascii
		$s6 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <40KB and all of them )
}