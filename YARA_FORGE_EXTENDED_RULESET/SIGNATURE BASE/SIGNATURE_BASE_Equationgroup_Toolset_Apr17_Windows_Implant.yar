rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Windows_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "a82aac49-8843-5420-8b87-f3d7431bc63f"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L3216-L3229"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5b6b349c98a328b4bbdd6d8718af8477c36ec219bb0076dd56998395d0ef5f32"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d38ce396926e45781daecd18670316defe3caf975a3062470a87c1d181a61374"

	strings:
		$s2 = "0#0)0/050;0M0Y0h0|0" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and all of them )
}
