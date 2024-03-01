rule SIGNATURE_BASE_Equation_Kaspersky_Equationlaserinstaller : FILE
{
	meta:
		description = "Equation Group Malware - EquationLaser Installer"
		author = "Florian Roth (Nextron Systems)"
		id = "15fd5668-36f2-556c-8150-225d3cbd4121"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "http://goo.gl/ivt8EW"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L215-L236"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5e1f56c1e57fbff96d4999db1fd6dd0f7d8221df"
		logic_hash = "6f8ba26f5efaa7ec422171862e1b645472387395f0be3a4625d58de5f0584c0b"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "Failed to get Windows version" fullword ascii
		$s1 = "lsasrv32.dll and lsass.exe" fullword wide
		$s2 = "\\\\%s\\mailslot\\%s" fullword ascii
		$s3 = "%d-%d-%d %d:%d:%d Z" fullword ascii
		$s4 = "lsasrv32.dll" fullword ascii
		$s6 = "%s %02x %s" fullword ascii
		$s7 = "VIEWERS" fullword ascii
		$s8 = "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide

	condition:
		( uint16(0)==0x5a4d) and filesize <250000 and 6 of ($s*)
}
