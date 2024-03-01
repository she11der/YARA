rule SIGNATURE_BASE_APT30_Sample_14 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L351-L367"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b0740175d20eab79a5d62cdbe0ee1a89212a8472"
		logic_hash = "e5f352b1aa643b9508c01bbe921197ebd8992ec94036b869c55970f0177164d3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "AdobeReader.exe" fullword wide
		$s4 = "10.1.7.27" fullword wide
		$s5 = "Copyright 1984-2012 Adobe Systems Incorporated and its licensors. All ri" wide
		$s8 = "Adobe Reader" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
