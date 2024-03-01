rule SIGNATURE_BASE_APT30_Generic_H : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "1908e985-9634-51dc-8972-53afa13c26a3"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L10-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e4affe7dc01efc4d6c25aaae4679bc1f8fddd97794e351d30501eaeb8e1d1dea"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2a4c8752f3e7fde0139421b8d5713b29c720685d"
		hash2 = "4350e906d590dca5fcc90ed3215467524e0a4e3d"

	strings:
		$s0 = "\\Temp1020.txt" ascii
		$s1 = "Xmd.Txe" fullword ascii
		$s2 = "\\Internet Exp1orer" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
