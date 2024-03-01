rule SIGNATURE_BASE_Methodology_Suspicious_Shortcut_Workingdirremote_SMB : FILE
{
	meta:
		description = "Detects possible shortcut usage for .URL persistence"
		author = "@itsreallynick (Nick Carr)"
		id = "26e19fe3-c25c-53b0-9b41-c04803134bc2"
		date = "2019-09-27"
		modified = "2023-12-05"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L280-L297"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5d9caa64ac730d34a2dcfb3368f8302849275b6ee16fe31f20978d72382b0d73"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$icon = "WorkingDirectory=file://" nocase
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		$icon and any of ($url*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
