import "pe"

rule SIGNATURE_BASE_Equationgroup_PC_Level4_Flav_Exe : FILE
{
	meta:
		description = "EquationGroup Malware - file PC_Level4_flav_exe"
		author = "Florian Roth (Nextron Systems)"
		id = "eb93a798-4e7e-52dc-a39b-bfb63a58d250"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1523-L1541"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "975d327d5922e4b179a677501c2613186ea85299958a996dcdeb503b02495ff7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "33ba9f103186b6e52d8d69499512e7fbac9096e7c5278838127488acc3b669a9"

	strings:
		$s1 = "Extended Memory Runtime Process" fullword wide
		$s2 = "memess.exe" fullword wide
		$s3 = "\\\\.\\%hs" fullword ascii
		$s4 = ".?AVOpenSocket@@" fullword ascii
		$s5 = "Corporation. All rights reserved." fullword wide
		$s6 = "itanium" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
