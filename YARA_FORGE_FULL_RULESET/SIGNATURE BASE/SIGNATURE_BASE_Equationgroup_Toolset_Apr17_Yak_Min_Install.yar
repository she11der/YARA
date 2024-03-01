rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Yak_Min_Install : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "dc648deb-4220-5ec3-b95f-ff6cc463f79b"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2827-L2842"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f224c87c5626fee98dae5b4bbab2b4468bdd126ac63371ede53545d7cb177123"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f67214083d60f90ffd16b89a0ce921c98185b2032874174691b720514b1fe99e"

	strings:
		$s1 = "driver start" fullword ascii
		$s2 = "DeviceIoControl Error: %d" fullword ascii
		$s3 = "Phlook" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
