import "pe"

rule SIGNATURE_BASE_Equationgroup_Modifyaudit_Implant : FILE
{
	meta:
		description = "EquationGroup Malware - file modifyAudit_Implant.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "0321f6c0-2250-5991-a1d9-f0598e13c665"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1337-L1353"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ec8b54f3489b1eeef491b03641805e0e4db0b5cbbb67a3ae3d37dad184f54b01"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b7902809a15c4c3864a14f009768693c66f9e9234204b873d29a87f4c3009a50"

	strings:
		$s1 = "LSASS.EXE" fullword wide
		$s2 = "hNtQueryInformationProcess" fullword ascii
		$s3 = "hZwOpenProcess" fullword ascii
		$s4 = ".?AVFeFinallyFailure@@" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <90KB and ( all of ($s*))) or ( all of them )
}
