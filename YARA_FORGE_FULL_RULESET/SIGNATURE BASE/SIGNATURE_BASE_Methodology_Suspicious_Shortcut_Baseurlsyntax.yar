rule SIGNATURE_BASE_Methodology_Suspicious_Shortcut_Baseurlsyntax : FILE
{
	meta:
		description = "Detects possible shortcut usage for .URL persistence"
		author = "@itsreallynick (Nick Carr)"
		id = "cab7b573-d197-5afc-95a9-ef05a07c2b7a"
		date = "2019-09-27"
		modified = "2023-12-05"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L99-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4aa29bedb5689fe16c067f5ea933e56804085712c7469b138d8b658a30a7eb67"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$baseurl1 = "BASEURL=file://" nocase
		$baseurl2 = "[DEFAULT]" nocase
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		all of ($baseurl*) and any of ($url*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
