rule SIGNATURE_BASE_Shamoon2_Wiper : FILE
{
	meta:
		description = "Detects Shamoon 2.0 Wiper Component"
		author = "Florian Roth (Nextron Systems)"
		id = "6660a64c-daa4-59e6-aa65-55194cac600c"
		date = "2016-12-01"
		modified = "2023-12-05"
		reference = "https://goo.gl/jKIfGB"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_shamoon2.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "245b03d9606f2e391f53a60aa333c6b037aa1f013794d83b761813d54782b885"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c7fc1f9c2bed748b50a599ee2fa609eb7c9ddaeb9cd16633ba0d10cf66891d8a"
		hash2 = "128fa5815c6fee68463b18051c1a1ccdf28c599ce321691686b1efa4838a2acd"

	strings:
		$a1 = "\\??\\%s\\System32\\%s.exe" fullword wide
		$x1 = "IWHBWWHVCIDBRAFUASIIWURRTWRTIBIVJDGWTRRREFDEAEBIAEBJGGCSVUHGVJUHADIEWAFGWADRUWDTJBHTSITDVVBCIDCWHRHVTDVCDESTHWSUAEHGTWTJWFIRTBRB" wide
		$s1 = "UFWYNYNTS" fullword wide
		$s2 = "\\\\?\\ElRawDisk" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 2 of them ) or (3 of them )
}
