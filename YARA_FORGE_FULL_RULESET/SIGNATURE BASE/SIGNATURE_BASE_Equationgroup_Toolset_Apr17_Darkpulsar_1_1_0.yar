rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Darkpulsar_1_1_0 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "0f4f77d7-99bc-5c84-84bf-877c4e79c9f0"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1587-L1601"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "da8e1723da9e2d9955a3042bceb313d7d10903bfc078ba090c1c5a57be243b96"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b439ed18262aec387984184e86bfdb31ca501172b1c066398f8c56d128ba855a"

	strings:
		$x1 = "[%s] - Error upgraded DLL architecture does not match target architecture (0x%x)" fullword ascii
		$x2 = "[%s] - Error building DLL loading shellcode" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
