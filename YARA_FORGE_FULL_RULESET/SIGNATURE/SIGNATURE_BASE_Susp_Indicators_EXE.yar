rule SIGNATURE_BASE_Susp_Indicators_EXE : FILE
{
	meta:
		description = "Detects packed NullSoft Inst EXE with characteristics of NetWire RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "b4015c24-d18e-51eb-9854-8cc0e6dba4d0"
		date = "2018-01-05"
		modified = "2023-12-05"
		reference = "https://pastebin.com/8qaiyPxs"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_netwire_rat.yar#L11-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9cb66435b78893daa5583475b14f0df2a5e8612f3aaf5cb02160991ab4d57d1b"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6de7f0276afa633044c375c5c630740af51e29b6a6f17a64fbdd227c641727a4"

	strings:
		$s1 = "Software\\Microsoft\\Windows\\CurrentVersion"
		$s2 = "Error! Bad token or internal error" fullword ascii
		$s3 = "CRYPTBASE" fullword ascii
		$s4 = "UXTHEME" fullword ascii
		$s5 = "PROPSYS" fullword ascii
		$s6 = "APPHELP" fullword ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x4550 and filesize <700KB and all of them
}
