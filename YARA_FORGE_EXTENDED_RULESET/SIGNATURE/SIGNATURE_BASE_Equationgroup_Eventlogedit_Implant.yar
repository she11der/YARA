import "pe"

rule SIGNATURE_BASE_Equationgroup_Eventlogedit_Implant : FILE
{
	meta:
		description = "EquationGroup Malware - file EventLogEdit_Implant.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "40239dd0-4159-5c10-96b3-4f1e28c92d97"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1836-L1851"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1d391eaed77150ab2a26dfed60ebd82aa2c6802b6b604791fb78d08db7fe5ec9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0bb750195fbd93d174c2a8e20bcbcae4efefc881f7961fdca8fa6ebd68ac1edf"

	strings:
		$s1 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\%ls" fullword wide
		$s2 = "Ntdll.dll" fullword ascii
		$s3 = "hZwOpenProcess" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
