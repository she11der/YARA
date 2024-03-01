rule SIGNATURE_BASE_Methodology_Shortcut_Hotkey : FILE
{
	meta:
		description = "Detects possible shortcut usage for .URL persistence"
		author = "@itsreallynick (Nick Carr)"
		id = "0ce377c4-db9b-59fa-987b-a77eaf408765"
		date = "2019-09-27"
		modified = "2023-12-05"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L80-L97"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a48f7c1125218ee89f58f1517e81150038a5d71889d847e7690b13c818b32fb5"
		score = 50
		quality = 35
		tags = "FILE"

	strings:
		$hotkey = /[\x0a\x0d]HotKey=[1-9]/ nocase
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		$hotkey and any of ($url*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
