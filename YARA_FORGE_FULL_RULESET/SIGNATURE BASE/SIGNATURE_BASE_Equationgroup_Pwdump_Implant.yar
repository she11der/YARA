import "pe"

rule SIGNATURE_BASE_Equationgroup_Pwdump_Implant : FILE
{
	meta:
		description = "EquationGroup Malware - file pwdump_Implant.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "55984c20-539e-5e51-b3c4-caa6157c993d"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1395-L1410"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "20df7ef04154e317ee844545e541d62b3b8db4ac4800ba45a26b1092499c6e69"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "dfd5768a4825d1c7329c2e262fde27e2b3d9c810653585b058fcf9efa9815964"

	strings:
		$s1 = ".?AVFeFinallyFailure@@" fullword ascii
		$s8 = ".?AVFeFinallySuccess@@" fullword ascii
		$s3 = "\\system32\\win32k.sys" wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
