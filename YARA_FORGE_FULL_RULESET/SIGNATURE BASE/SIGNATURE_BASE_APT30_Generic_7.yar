rule SIGNATURE_BASE_APT30_Generic_7 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "bba40092-267b-5231-92f1-f222c9f888ee"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L1188-L1206"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b5a272cbeb46be9b120acdbe12d795eddc05765777e4157d818c2b91ea7b782b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "2415f661046fdbe3eea8cd276b6f13354019b1a6"
		hash1 = "e814914079af78d9f1b71000fee3c29d31d9b586"
		hash2 = "0263de239ccef669c47399856d481e3361408e90"

	strings:
		$s1 = "Xjapor_*ata" fullword
		$s2 = "Xjapor_o*ata" fullword
		$s4 = "Ouopai" fullword

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
