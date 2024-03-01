rule SIGNATURE_BASE_APT30_Sample_1 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L979-L996"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8cea83299af8f5ec6c278247e649c9d91d4cf3bc"
		logic_hash = "5f20b60b8721d62731708630a3443741c956304c553f651572282336995f6d4f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "#hostid" fullword ascii
		$s1 = "\\Windows\\C" ascii
		$s5 = "TimUmove" fullword ascii
		$s6 = "Moziea/4.0 (c" fullword ascii
		$s7 = "StartupNA" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
