rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Mcl_Ntmemory_Std : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "608218a8-7642-5ec4-8c07-87248649f022"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L2168-L2183"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5d3c76cf0ca0f798e1ca3c0a1b88c3bb425f1c36439842c4c33247dfcb44a877"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "087db4f2dbf8e0679de421fec8fb2e6dd50625112eb232e4acc1408cc0bcd2d7"

	strings:
		$op1 = { 44 24 37 50 c6 44 24 38 72 c6 44 }
		$op2 = { 44 24 33 6f c6 44 24 34 77 c6 }
		$op3 = { 3b 65 c6 44 24 3c 73 c6 44 24 3d 73 c6 44 24 3e }

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
