rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Doublefeaturedll_Dll_2 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "f77fd49f-815b-5fb9-a3d7-8721edf79b28"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L2957-L2974"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0d6751ebfb2541c86b74583b7867de0a193ca106bf77337c8b10f15cdeb596bd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f265defd87094c95c7d3ddf009d115207cd9d4007cf98629e814eda8798906af"
		hash2 = "8d62ca9e6d89f2b835d07deb5e684a576607e4fe3740f77c0570d7b16ebc2985"
		hash3 = "634a80e37e4b32706ad1ea4a2ff414473618a8c42a369880db7cc127c0eb705e"

	strings:
		$s1 = ".dllfD" fullword ascii
		$s2 = "Khsppxu" fullword ascii
		$s3 = "D$8.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 2 of them )
}
