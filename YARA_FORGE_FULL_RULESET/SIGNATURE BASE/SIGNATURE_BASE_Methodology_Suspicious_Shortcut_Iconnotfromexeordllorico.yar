rule SIGNATURE_BASE_Methodology_Suspicious_Shortcut_Iconnotfromexeordllorico : FILE
{
	meta:
		description = "Detects possible shortcut usage for .URL persistence"
		author = "@itsreallynick (Nick Carr)"
		id = "82d0483f-48ee-5d0c-ba7d-73d9e9455423"
		date = "2019-09-27"
		modified = "2023-12-05"
		reference = "https://twitter.com/ItsReallyNick/status/1176229087196696577"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L161-L179"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "957fe9f24d08033cf6e29d7e202e04bfb579577d3850a99e97da6b70924ae88e"
		score = 50
		quality = 35
		tags = "FILE"

	strings:
		$icon = "IconFile="
		$icon_negate = /[\x0a\x0d]IconFile=[^\x0d]*\.(dll|exe|ico)\x0d/ nocase
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		any of ($url*) and $icon and not $icon_negate and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
