rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Easybee_1_0_1 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "f170ed34-f7d1-5eb2-9400-4308b6b39388"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1802-L1816"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e3488a1d686b9ad468553cfe2c939e70ea6b9a21409df8b06bb54418495576ec"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "59c17d6cb564edd32c770cd56b5026e4797cf9169ff549735021053268b31611"

	strings:
		$x1 = "@@for /f \"delims=\" %%i in ('findstr /smc:\"%s\" *.msg') do if not \"%%MsgFile1%%\"==\"%%i\" del /f \"%%i\"" fullword ascii
		$x2 = "Logging out of WebAdmin (as target account)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
