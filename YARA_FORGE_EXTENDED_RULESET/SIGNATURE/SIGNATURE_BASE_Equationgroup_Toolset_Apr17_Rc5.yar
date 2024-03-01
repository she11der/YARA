rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Rc5 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "854c1726-4ba4-5464-a765-4dd154a1b166"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L3027-L3043"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6d9ba73fe2a6da99ba44b00bcb5ecf51e983ac245fd5c6e620d35e8120514464"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "69e2c68c6ea7be338497863c0c5ab5c77d5f522f0a84ab20fe9c75c7f81318eb"

	strings:
		$s1 = "Usage: %s [d|e] session_key ciphertext" fullword ascii
		$s2 = "where session_key and ciphertext are strings of hex" fullword ascii
		$s3 = "d = decrypt mode, e = encrypt mode" fullword ascii
		$s4 = "Bad mode, should be 'd' or 'e'" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}
