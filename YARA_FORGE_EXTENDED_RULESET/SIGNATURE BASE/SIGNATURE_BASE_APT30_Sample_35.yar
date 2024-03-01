rule SIGNATURE_BASE_APT30_Sample_35 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "8a30720b-06da-5a82-8bab-bf06121afd68"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L962-L977"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "df48a7cd6c4a8f78f5847bad3776abc0458499a6"
		logic_hash = "a70d9471215ddcfe84a39b33f53c4114b205aa2cc95cd93081afe442ee2b8b42"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "WhBoyIEXPLORE.EXE.exe" fullword ascii
		$s5 = "Startup>A" fullword ascii
		$s18 = "olhelp32Snapshot" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
