rule SIGNATURE_BASE_Equationgroup_X86_Linux_Exactchange : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "b39e0c6e-b427-5085-99f8-88b2e00bb110"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1474-L1490"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9365eb74a364eb83150672919ea1abe635465fe3239fff26ba91037c74971466"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "dfecaf5b85309de637b84a686dd5d2fca9c429e8285b7147ae4213c1f49d39e6"
		hash2 = "6ef6b7ec1f1271503957cf10bb6b1bfcedb872d2de3649f225cf1d22da658bec"

	strings:
		$x1 = "kernel has 4G/4G split, not exploitable" fullword ascii
		$x2 = "[+] kernel stack size is %d" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <1000KB and 1 of them )
}
