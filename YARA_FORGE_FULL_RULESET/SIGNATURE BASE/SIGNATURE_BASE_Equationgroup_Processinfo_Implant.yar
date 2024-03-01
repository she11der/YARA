import "pe"

rule SIGNATURE_BASE_Equationgroup_Processinfo_Implant : FILE
{
	meta:
		description = "EquationGroup Malware - file processinfo_Implant.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "b110d819-2298-507b-91bb-2787bb11322e"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1543-L1558"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b0aace3c6fa20c5bb238264b2aa484d548945a4c2ccb65482cce71427f061604"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "aadfa0b1aec4456b10e4fb82f5cfa918dbf4e87d19a02bcc576ac499dda0fb68"

	strings:
		$s1 = "hZwOpenProcessToken" fullword ascii
		$s2 = "hNtQueryInformationProcess" fullword ascii
		$s3 = "No mapping" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and all of them )
}
