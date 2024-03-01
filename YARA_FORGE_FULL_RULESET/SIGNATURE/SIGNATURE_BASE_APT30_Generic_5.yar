rule SIGNATURE_BASE_APT30_Generic_5 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e00a670e-cd95-515f-8109-219ce5121ba4"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L1142-L1163"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a9d93d7dbf8c5e97ce77cf3fef4941a01c5b1c6bcee40c6f4ca7117d8aee289e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "cb4833220c508182c0ccd4e0d5a867d6c4e675f8"
		hash1 = "dfc9a87df2d585c479ab02602133934b055d156f"
		hash2 = "bf59d5ff7d38ec5ffb91296e002e8742baf24db5"

	strings:
		$s0 = "regsvr32 /s \"%ProgramFiles%\\Norton360\\Engine\\5.1.0.29\\ashelper.dll\"" fullword
		$s1 = "name=\"ftpserver.exe\"/>" fullword
		$s2 = "LiveUpdate.EXE" fullword wide
		$s3 = "<description>FTP Explorer</description>" fullword
		$s4 = "\\ashelper.dll"
		$s5 = "LiveUpdate" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
