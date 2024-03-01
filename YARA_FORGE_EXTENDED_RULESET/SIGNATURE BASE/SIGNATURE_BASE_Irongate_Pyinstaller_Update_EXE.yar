rule SIGNATURE_BASE_Irongate_Pyinstaller_Update_EXE : FILE
{
	meta:
		description = "Detects a PyInstaller file named update.exe as mentioned in the IronGate APT"
		author = "Florian Roth (Nextron Systems)"
		id = "f8d1b97e-86d9-547f-a212-a84fb068af3c"
		date = "2016-06-04"
		modified = "2023-01-06"
		reference = "https://goo.gl/Mr6M2J"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_irongate.yar#L42-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b55e02af900b3510743502bd72d5e14c9235985b5a7b05def0f5c462b28f2216"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "2044712ceb99972d025716f0f16aa039550e22a63000d2885f7b7cd50f6834e0"

	strings:
		$s1 = "bpython27.dll" fullword ascii
		$s5 = "%s%s.exe" fullword ascii
		$s6 = "bupdate.exe.manifest" fullword ascii
		$s9 = "bunicodedata.pyd" fullword ascii
		$s11 = "distutils.sysconfig(" ascii
		$s16 = "distutils.debug(" ascii
		$s18 = "supdate" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
