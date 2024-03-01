rule SIGNATURE_BASE_APT30_Sample_23 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "9366dd34-9967-5b40-935e-4b0d8f2f5e9e"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L617-L637"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9865e24aadb4480bd3c182e50e0e53316546fc01"
		logic_hash = "64ff048b061431e0834ac40bfccb0d9e8ca60ffb022578ef910e6ffc511be6ed"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "hostid" ascii
		$s1 = "\\Window" ascii
		$s2 = "%u:%u%s" fullword ascii
		$s5 = "S2tware\\Mic" ascii
		$s6 = "la/4.0 (compa" ascii
		$s7 = "NameACKernel" fullword ascii
		$s12 = "ToWideChc[lo" fullword ascii
		$s14 = "help32SnapshotfL" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
