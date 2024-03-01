rule SIGNATURE_BASE_Sql1433_SQL : FILE
{
	meta:
		description = "Chinese Hacktool Set - file SQL.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "fb4c5958-2e4e-5231-b0db-eca6bc3d823a"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1699-L1715"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "025e87deadd1c50b1021c26cb67b76b476fafd64"
		logic_hash = "5ceecc4f345cb603a0b03180f3f09f97e5f951b5d75c469aefffe3ec62916a8f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 31 00 34 00 33 00 33 }
		$s1 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 31 00 2C 00 34 00 2C 00 33 00 2C 00 33 }

	condition:
		uint16(0)==0x5a4d and filesize <90KB and all of them
}
