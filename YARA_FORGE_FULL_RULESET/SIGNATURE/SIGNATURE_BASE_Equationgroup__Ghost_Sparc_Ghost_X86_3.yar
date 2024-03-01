rule SIGNATURE_BASE_Equationgroup__Ghost_Sparc_Ghost_X86_3 : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- from files ghost_sparc, ghost_x86"
		author = "Florian Roth (Nextron Systems)"
		id = "ccc9c9be-8f78-5071-a11e-47f994cf8f08"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L894-L912"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c4ad8e06934c1ece520863951f14cbf86d1bc4bba97aede1d58def1e5c7df4eb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "d5ff0208d9532fc0c6716bd57297397c8151a01bf4f21311f24e7a72551f9bf1"
		hash2 = "82c899d1f05b50a85646a782cddb774d194ef85b74e1be642a8be2c7119f4e33"

	strings:
		$x1 = "Usage: %s [-v os] [-p] [-r] [-c command] [-a attacker] target" fullword ascii
		$x2 = "Sending shellcode as part of an open command..." fullword ascii
		$x3 = "cmdshellcode" fullword ascii
		$x4 = "You will not be able to run the shellcode. Exiting..." fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <70KB and 1 of them ) or (2 of them )
}
