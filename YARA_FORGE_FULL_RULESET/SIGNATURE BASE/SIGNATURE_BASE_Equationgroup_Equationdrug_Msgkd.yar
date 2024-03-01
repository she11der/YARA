import "pe"

rule SIGNATURE_BASE_Equationgroup_Equationdrug_Msgkd : FILE
{
	meta:
		description = "EquationGroup Malware - file msgkd.ex_"
		author = "Florian Roth (Nextron Systems)"
		id = "41019119-9bf4-5a45-b74b-f75ab7738821"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1704-L1718"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "60336294ef5fa0221fc6a0e8b05bb279ac0e167024568cd9efa78e678e763704"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "25eec68fc9f0d8d1b5d72c9eae7bee29035918e9dcbeab13e276dec4b2ad2a56"

	strings:
		$s1 = "KEysud" fullword ascii
		$s2 = "XWWWPWS" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
