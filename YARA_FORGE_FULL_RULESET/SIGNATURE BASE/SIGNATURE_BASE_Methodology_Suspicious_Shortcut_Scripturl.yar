rule SIGNATURE_BASE_Methodology_Suspicious_Shortcut_Scripturl : FILE
{
	meta:
		description = "Detects possible shortcut usage for .URL persistence"
		author = "@itsreallynick (Nick Carr)"
		id = "2f55f8a9-4e4b-5480-9042-da6bb66b2e06"
		date = "2019-09-27"
		modified = "2023-12-05"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L241-L259"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ece0013dbc9836fa800f99a10ab46c1eb081e1c04fe45fe17be26ffac1d464e9"
		score = 50
		quality = 35
		tags = "FILE"

	strings:
		$file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=[^\x0d]*script:/ nocase
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		any of ($url*) and any of ($file*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
