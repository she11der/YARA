rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Esteemaudittouch_2_1_0 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "bb66245e-1261-50bd-8666-75fc4c52ad84"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1684-L1698"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "f4e62ec7a68115d5ff155ea94fb2c99b9177e928533338a111e531c694ff7b8f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f6b9caf503bb664b22c6d39c87620cc17bdb66cef4ccfa48c31f2a3ae13b4281"

	strings:
		$x1 = "[-] Touching the target failed!" fullword ascii
		$x2 = "[-] OS fingerprint not complete - 0x%08x!" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
