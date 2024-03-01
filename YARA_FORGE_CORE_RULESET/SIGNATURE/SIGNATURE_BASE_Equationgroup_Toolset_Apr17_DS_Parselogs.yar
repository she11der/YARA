rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_DS_Parselogs : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "1906c0fc-3fbc-5995-8789-f1c02e574672"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2347-L2362"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e4c35476b512378d1e3c7e7e3e9dae16adb0d4de4ecab143d034110836c11d0d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0228691d63038b072cdbf50782990d505507757efbfa87655bb2182cf6375956"

	strings:
		$x1 = "* Size (%d) of remaining capture file is too small to contain a valid header" fullword wide
		$x2 = "* Capture header not found at start of buffer" fullword wide
		$x3 = "Usage: %ws <capture_file> <results_prefix>" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}
