rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__Addresource : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "cbba38fa-a906-5463-ae46-2b9c9f1bf8e0"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L3381-L3398"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e59863ac7f1147cdbc34cbd2b09183487999d9f01974279c7ccc0c5af7a99976"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "e83e4648875d4c4aa8bc6f3c150c12bad45d066e2116087cdf78a4a4efbab6f0"
		hash2 = "5a04d65a61ef04f5a1cbc29398c767eada367459dc09c54c3f4e35015c71ccff"

	strings:
		$s1 = "%s cm 10 2000 \"c:\\MY DIR\\myapp.exe\" c:\\MyResourceData.dat" fullword ascii
		$s2 = "<PE path> - the path to the PE binary to which to add the resource." fullword ascii
		$s3 = "Unable to get path for target binary." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 2 of them )
}
