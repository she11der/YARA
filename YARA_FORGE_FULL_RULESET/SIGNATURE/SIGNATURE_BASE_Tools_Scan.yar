rule SIGNATURE_BASE_Tools_Scan : FILE
{
	meta:
		description = "Chinese Hacktool Set - file scan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4601d4d0-2b7e-5937-87b6-df80ab373752"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1451-L1466"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c580a0cc41997e840d2c0f83962e7f8b636a5a13"
		logic_hash = "d8bf2e4a4634f74ce548a5824090502f2ccef382bdbcaf795df711e88a325912"
		score = 75
		quality = 81
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Shanlu Studio" fullword wide
		$s3 = "_AutoAttackMain" fullword ascii
		$s4 = "_frmIpToAddr" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}
