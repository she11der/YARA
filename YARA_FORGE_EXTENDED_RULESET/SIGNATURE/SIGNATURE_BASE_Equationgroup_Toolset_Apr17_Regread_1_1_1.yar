rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Regread_1_1_1 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "99a2b146-a277-5917-9a84-3d396d2c8bf9"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L1818-L1832"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5bf833d7fb073ad74037cf6df4729c75d50641a46a962aee8deac19e31b74419"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "722f034ba634f45c429c7dafdbff413c08976b069a6b30ec91bfa5ce2e4cda26"

	strings:
		$s1 = "[+] Connected to the Registry Service" fullword ascii
		$s2 = "f08d49ac41d1023d9d462d58af51414daff95a6a" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and 1 of them )
}
