rule SIGNATURE_BASE_Methodology_Suspicious_Shortcut_SMB_URL : FILE
{
	meta:
		description = "Detects remote SMB path for .URL persistence"
		author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
		id = "e23609a1-9b18-5a56-92ee-c7f84c966865"
		date = "2019-09-27"
		modified = "2023-12-05"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L21-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e0bef7497fcb284edb0c65b59d511830"
		logic_hash = "4903c8f4bb08e799f6787ad29cf7688f354f97a065bcd24c58d3ccd3778a6a15"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$file = /URL=file:\/\/[a-z0-9]/ nocase
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		$file and any of ($url*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
