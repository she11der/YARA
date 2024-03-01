import "pe"

rule SIGNATURE_BASE_Equationgroup_Equationdrug_Gen_2 : FILE
{
	meta:
		description = "EquationGroup Malware - file PortMap_Implant.dll"
		author = "Auto Generated"
		id = "662ee1cf-b837-5362-84a8-1af7335d5e1b"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1560-L1574"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "fcbc518d23dc21d482abcac29505c5404fc9e309554ca7dc9f1014adbff83e1a"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "964762416840738b1235ed4ae479a4b117b8cdcc762a6737e83bc2062c0cf236"

	strings:
		$op1 = { 0c 2b ca 8a 04 11 3a 02 75 01 47 42 4e 75 f4 8b }
		$op2 = { 14 83 c1 05 80 39 85 75 0c 80 79 01 c0 75 06 80 }
		$op3 = { eb 3d 83 c0 06 33 f6 80 38 ff 75 2c 80 78 01 15 }

	condition:
		( uint16(0)==0x5a4d and filesize <250KB and all of them )
}
