import "pe"

rule SIGNATURE_BASE_Equationgroup_Equationdrug_Mstcp32 : FILE
{
	meta:
		description = "EquationGroup Malware - file mstcp32.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "bed26a7b-933f-5578-b65c-65179959050d"
		date = "2017-01-13"
		modified = "2023-01-06"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1464-L1485"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "aff97f8360a0c24bfde6a1b2616749d6cad3b19993716231d32b8bb59579c638"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "26215bc56dc31d2466d72f1f4e1b6388e62606e9949bc41c28968fcb9a9d60a6"

	strings:
		$s1 = "mstcp32.sys" fullword wide
		$s2 = "p32.sys" fullword ascii
		$s3 = "\\Registry\\User\\CurrentUser\\" wide
		$s4 = "\\DosDevices\\%ws" wide
		$s5 = "\\Device\\%ws_%ws" wide
		$s6 = "sys\\mstcp32.dbg" fullword ascii
		$s7 = "%ws%03d%ws%wZ" fullword wide
		$s8 = "TCP/IP driver" fullword wide
		$s9 = "\\Device\\%ws" wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 7 of them ) or ( all of them )
}
