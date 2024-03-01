rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Eternalromance_2 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "40066023-ede9-5669-8b4d-a26a693d8818"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L1872-L1889"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "481a08bc73ac66245c0712599a61cccdf5127276a09a67cf894f76b7763c5c9b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "f1ae9fdbb660aae3421fd3e5b626c1e537d8e9ee2f9cd6d56cb70b6878eaca5d"
		hash2 = "b99c3cc1acbb085c9a895a8c3510f6daaf31f0d2d9ccb8477c7fb7119376f57b"
		hash3 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"

	strings:
		$x1 = "[+] Backdoor shellcode written" fullword ascii
		$x2 = "[*] Attempting exploit method %d" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 1 of them )
}
