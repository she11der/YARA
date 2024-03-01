rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Drivers_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "727a0a8c-0019-53e9-9632-c610299305fc"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2415-L2431"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "45190a317f3d293dbc3015873080d1253bfb3298008f5dea69ab1a5780a70721"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ee8b048f1c6ba821d92c15d614c2d937c32aeda7b7ea0943fd4f640b57b1c1ab"

	strings:
		$s1 = ".?AVFeFinallyFailure@@" fullword ascii
		$s2 = "hZwLoadDriver" fullword ascii
		$op1 = { b0 01 e8 58 04 00 00 c3 33 }

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and all of them )
}
