rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Wmi_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "e058d2cc-b963-55bc-9bdd-468f64fe8e6f"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2772-L2785"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "69754b6f26292aa1a457c71d079d934ce75794624c38e9d19c84ceb77a5fb26d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "de08d6c382faaae2b4b41b448b26d82d04a8f25375c712c12013cb0fac3bc704"

	strings:
		$x1 = "SELECT ProcessId,Description,ExecutablePath FROM Win32_Process" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and all of them )
}
