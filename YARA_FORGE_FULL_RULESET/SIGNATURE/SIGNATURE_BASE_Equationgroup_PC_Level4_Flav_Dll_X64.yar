import "pe"

rule SIGNATURE_BASE_Equationgroup_PC_Level4_Flav_Dll_X64 : FILE
{
	meta:
		description = "EquationGroup Malware - file PC_Level4_flav_dll_x64"
		author = "Florian Roth (Nextron Systems)"
		id = "f05dd0b6-106c-5d1d-ba09-4ac3035e7030"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1506-L1521"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9c874581567909055deeae4f992bd99c1e08d5f62655d1cc9a7316beb8513d8f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "25a2549031cb97b8a3b569b1263c903c6c0247f7fff866e7ec63f0add1b4921c"

	strings:
		$s1 = "wship.dll" fullword wide
		$s2 = "   IP:      " fullword ascii
		$s3 = "\\\\.\\%hs" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
