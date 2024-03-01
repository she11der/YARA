import "pe"

rule SIGNATURE_BASE_Equationgroup_Modifygroup_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file ModifyGroup_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "82c9617a-3d78-525f-a507-76c87aad7c59"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1805-L1819"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8fe5102cacd9149a0ed60440c563953d487aa2b28a3b947d821d0cc3f3396a4a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "dfb38ed2ca3870faf351df1bd447a3dc4470ed568553bf83df07bf07967bf520"

	strings:
		$s1 = "Modify Privileges failed" fullword wide
		$s2 = "Given privilege name not found" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
