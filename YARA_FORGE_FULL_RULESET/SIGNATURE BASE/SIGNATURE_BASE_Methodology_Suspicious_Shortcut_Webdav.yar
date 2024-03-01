rule SIGNATURE_BASE_Methodology_Suspicious_Shortcut_Webdav : FILE
{
	meta:
		description = "Detects possible shortcut usage for .URL persistence"
		author = "@itsreallynick (Nick Carr)"
		id = "cd660b84-d7c6-52fc-9e1d-76450e5262b1"
		date = "2019-09-27"
		modified = "2023-12-05"
		reference = "https://twitter.com/cglyer/status/1176243536754282497"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L222-L239"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4fec084392140245eeb25bb512f3a4631ec6be08c197ec130a907fc118161197"
		score = 50
		quality = 35
		tags = "FILE"

	strings:
		$file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=\s*\/\/[A-Za-z0-9]/
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		any of ($url*) and any of ($file*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
