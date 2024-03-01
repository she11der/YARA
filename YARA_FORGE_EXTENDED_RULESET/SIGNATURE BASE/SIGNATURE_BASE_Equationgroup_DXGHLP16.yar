import "pe"

rule SIGNATURE_BASE_Equationgroup_DXGHLP16 : FILE
{
	meta:
		description = "EquationGroup Malware - file DXGHLP16.SYS"
		author = "Florian Roth (Nextron Systems)"
		id = "d9e39c22-f606-5d9c-a5e2-e536b8566595"
		date = "2017-01-13"
		modified = "2023-01-06"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1681-L1702"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5244cef876af4c0c02109599e6250254c854ed5c9bd2d0ccc44676dca21a1650"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "fcfb56fa79d2383d34c471ef439314edc2239d632a880aa2de3cea430f6b5665"

	strings:
		$s1 = "DXGHLP16.SYS" fullword wide
		$s2 = "P16.SYS" fullword ascii
		$s3 = "\\Registry\\User\\CurrentUser\\" wide
		$s4 = "\\DosDevices\\%ws" wide
		$s5 = "\\Device\\%ws_%ws" wide
		$s6 = "ct@SYS\\DXGHLP16.dbg" fullword ascii
		$s7 = "%ws%03d%ws%wZ" fullword wide
		$s8 = "TCP/IP driver" fullword wide
		$s9 = "\\Device\\%ws" wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
