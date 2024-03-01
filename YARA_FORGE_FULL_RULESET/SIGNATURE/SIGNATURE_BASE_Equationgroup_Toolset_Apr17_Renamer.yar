rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Renamer : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "b5a7c8a8-c30d-5667-a458-6962a24061d3"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2547-L2561"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4941f31be6674499b202a3071d795317e6d97fb19088ea370180708e3d04bca7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9c30331cb00ae8f417569e9eb2c645ebbb36511d2d1531bb8d06b83781dfe3ac"

	strings:
		$s1 = "FILE_NAME_CONVERSION.LOG" fullword wide
		$s2 = "Log file exists. You must delete it!!!" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and all of them )
}
