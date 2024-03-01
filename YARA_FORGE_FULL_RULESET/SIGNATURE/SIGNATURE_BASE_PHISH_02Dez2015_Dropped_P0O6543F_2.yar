rule SIGNATURE_BASE_PHISH_02Dez2015_Dropped_P0O6543F_2 : FILE
{
	meta:
		description = "Phishing Wave used MineExplorer Game by WangLei - file p0o6543f.exe.4"
		author = "Florian Roth (Nextron Systems)"
		id = "ed6f6dc8-5b5d-5a6f-a2a0-cb8a34c8931f"
		date = "2015-12-03"
		modified = "2023-12-05"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_phish_gina_dec15.yar#L31-L47"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f5eb21d0f635171e1edcfecc909bc3508dfb6c32e7fdd7263edd5cd98e6ba411"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d6b21ded749b57042eede07c3af1956a3c9f1faddd22d2f78e43003a11ae496f"
		hash2 = "561b16643992b92d37cf380bc2ed7cd106e4dcaf25ca45b4ba876ce59533fb02"

	strings:
		$s1 = "Email: W0067@990.net" fullword wide
		$s2 = "MineExplorer Version 1.0" fullword wide
		$s6 = "Copy Rights by WangLei 1999.4" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}
