import "pe"

rule SIGNATURE_BASE_Equationgroup_Nethide_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file nethide_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "39e96239-2189-5993-90ba-27e47f7bfdea"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1487-L1504"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "70e96a8ef5f75e05b3f6d32b9b8392316c3a70cb479549a3700134435b690473"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "137749c0fbb8c12d1a650f0bfc73be2739ff084165d02e4cb68c6496d828bf1d"

	strings:
		$x1 = "Error: Attempt to hide all TCP connections (any:any)." fullword wide
		$x2 = "privilegeRunInKernelMode failed" fullword wide
		$x3 = "Failed to unhide requested connection" fullword wide
		$x4 = "Nethide running in USER_MODE" fullword wide
		$x5 = "Not enough slots for all of the list.  Some entries may have not been hidden." fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them ) or ( all of them )
}
