import "pe"

rule SIGNATURE_BASE_Equationgroup_Getadmin_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file GetAdmin_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "3bbe0553-a5a3-5207-a94e-ad978606d9a4"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1789-L1802"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5bff3858c59b1bb44c5e24ca5f77d8e1e582224cc1caad3955d1adb0efea318a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e1c9c9f031d902e69e42f684ae5b35a2513f7d5f8bca83dfbab10e8de6254c78"

	strings:
		$x1 = "Current user is System -- unable to join administrators group" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
