import "pe"

rule SIGNATURE_BASE_Equationgroup_Modifyaudit_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file modifyAudit_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "9dcfa774-0048-5bd9-ba7d-87bbdff9567a"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1355-L1372"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a908d44b831a27bb584c5da936346f77f0e205658ec2ebe0e600004645894593"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2a1f2034e80421359e3bf65cbd12a55a95bd00f2eb86cf2c2d287711ee1d56ad"

	strings:
		$s1 = "Read of audit related process memory failed" fullword wide
		$s2 = "** This may indicate that another copy of modify_audit is already running **" fullword wide
		$s3 = "Pattern match of code failed" fullword wide
		$s4 = "Base for necessary auditing dll not found" fullword wide
		$s5 = "Security auditing has been disabled" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 3 of them ) or ( all of them )
}
