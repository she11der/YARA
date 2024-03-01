rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Setcallback : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "3c06fc74-2e75-5348-bb62-30c724de1414"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L3258-L3272"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "63a17dd56874085753cae92f70d6248ceaac6eaea99fda0d3a551e4988a73895"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a8854f6b01d0e49beeb2d09e9781a6837a0d18129380c6e1b1629bc7c13fdea2"

	strings:
		$s2 = "*NOTE: This version of SetCallback does not work with PeddleCheap versions prior" fullword ascii
		$s3 = "USAGE: SetCallback <input file> <output file>" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
