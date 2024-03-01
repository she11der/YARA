rule SIGNATURE_BASE_Equationgroup_Cursehelper_Win2K_I686_V_2_2_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "1c24aa6a-74ab-5832-876b-5cab43dc6bb7"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1084-L1100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f6c92fc3540750a1223682b1672575b3a3120f5ebf63190a9b31d7e4e5ce13c7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5ac6fde8a06f4ade10d672e60e92ffbf78c4e8db6b5152e23171f6f53af0bfe1"

	strings:
		$s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/{}" fullword ascii
		$op1 = { 8d b5 48 ff ff ff 89 34 24 e8 56 2a 00 00 c7 44 }
		$op2 = { e9 a2 f2 ff ff ff 85 b4 fe ff ff 8b 95 a8 fe ff }

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and all of them )
}
