rule SIGNATURE_BASE_APT30_Generic_6 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "dfd104bd-daf4-593a-b161-61f43aec048c"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L1165-L1186"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ff7473e43e11e31fe6ad997009834f661a0120317e479184410456c99f72b613"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "b9aafb575d3d1732cb8fdca5ea226cebf86ea3c9"
		hash1 = "2c5e347083b77c9ead9e75d41e2fabe096460bba"
		hash2 = "5d39a567b50c74c4a921b5f65713f78023099933"

	strings:
		$s0 = "GetStar" fullword
		$s1 = ".rdUaS" fullword
		$s2 = "%sOTwp/&A\\L" fullword
		$s3 = "a Encrt% Flash Disk" fullword
		$s4 = "ypeAutoRuChec" fullword
		$s5 = "NoDriveT" fullword

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
