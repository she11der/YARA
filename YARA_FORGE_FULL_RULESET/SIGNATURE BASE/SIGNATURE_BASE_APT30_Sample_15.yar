rule SIGNATURE_BASE_APT30_Sample_15 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L369-L387"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7a8576804a2bbe4e5d05d1718f90b6a4332df027"
		logic_hash = "5179f39bdcb064f55479ad147a019dd0b3874783c6bad650e84cfd9d0430bb70"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\Windo" ascii
		$s2 = "HHOSTR" ascii
		$s3 = "Softwa]\\Mic" ascii
		$s4 = "Startup'T" fullword ascii
		$s17 = "help32Snapshot0L" fullword ascii
		$s18 = "TimUmoveH" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
