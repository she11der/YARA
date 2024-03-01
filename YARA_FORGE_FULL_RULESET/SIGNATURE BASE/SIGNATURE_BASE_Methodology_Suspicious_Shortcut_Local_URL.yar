rule SIGNATURE_BASE_Methodology_Suspicious_Shortcut_Local_URL : FILE
{
	meta:
		description = "Detects local script usage for .URL persistence"
		author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
		id = "438d9323-cb6a-5f5d-af71-76692b93436a"
		date = "2019-09-27"
		modified = "2023-12-05"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e95e5e97760d9b565184c588fdafe8408cdab61959aee5221485df53ef5f51d6"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$file = "URL=file:///" nocase
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		$file and any of ($url*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
