rule SIGNATURE_BASE_Equationgroup_Crypttool___FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file cryptTool"
		author = "Florian Roth (Nextron Systems)"
		id = "e1f4e010-9c42-5b8a-8feb-2885b99307fe"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L50-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "ae2d5eda038326376511450e1f5bd2bbf6264d23df013b005b322d70eb6266a0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "96947ad30a2ab15ca5ef53ba8969b9d9a89c48a403e8b22dd5698145ac6695d2"

	strings:
		$s1 = "The encryption key is " fullword ascii
		$s2 = "___tempFile2.out" ascii

	condition:
		( uint16(0)==0x457f and filesize <200KB and all of them )
}