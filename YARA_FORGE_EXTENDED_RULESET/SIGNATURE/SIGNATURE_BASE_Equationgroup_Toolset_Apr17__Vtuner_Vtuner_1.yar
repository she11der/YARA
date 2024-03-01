rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__Vtuner_Vtuner_1 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "3794f30b-39dc-59eb-9fd3-4c7837bfd47d"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L3295-L3315"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8c161b36599b11264c31c54b94d6bdba53b3f13d27861ededc9f03bba394b775"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "3e6bec0679c1d8800b181f3228669704adb2e9cbf24679f4a1958e4cdd0e1431"
		hash2 = "b0d2ebf455092f9d1f8e2997237b292856e9abbccfbbebe5d06b382257942e0e"

	strings:
		$s1 = "Unable to get -w hash.  %x" fullword wide
		$s2 = "!\"invalid instruction mnemonic constant Id3vil\"" fullword wide
		$s4 = "Unable to set -w provider. %x" fullword wide
		$op0 = { 2b c7 50 e8 3a 8c ff ff ff b6 c0 }
		$op2 = { a1 8c 62 47 00 81 65 e0 ff ff ff 7f 03 d8 8b c1 }

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 2 of them )
}
