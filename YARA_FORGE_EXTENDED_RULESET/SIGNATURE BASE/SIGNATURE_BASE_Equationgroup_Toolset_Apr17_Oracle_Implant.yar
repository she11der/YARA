rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Oracle_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "6ff4cd21-1060-5901-842e-c04bde4f16ec"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L2364-L2379"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "568a5d103527e6fd99bbac8d49a2d667f464fd16d5bf276f98c88c39e129b58b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8e9be4960c62ed7f210ce08f291e410ce0929cd3a86fe70315d7222e3df4587e"

	strings:
		$op0 = { fe ff ff ff 48 89 9c 24 80 21 00 00 48 89 ac 24 }
		$op1 = { e9 34 11 00 00 b8 3e 01 00 00 e9 2a 11 00 00 b8 }
		$op2 = { 48 8b ca e8 bf 84 00 00 4c 8b e0 8d 34 00 44 8d }

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and all of them )
}
