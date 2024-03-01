rule SIGNATURE_BASE_Methodology_Suspicious_Shortcut_Lolcommand : FILE
{
	meta:
		description = "Detects possible shortcut usage for .URL persistence"
		author = "@itsreallynick (Nick Carr)"
		id = "061e7919-17f1-5774-ad7d-fc964dc9a947"
		date = "2019-09-27"
		modified = "2021-02-14"
		reference = "https://twitter.com/ItsReallyNick/status/1176601500069576704"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L201-L219"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4ac9a555e61303a173443de2a189536c8ea0fc32ee73c589dd104275c7967c57"
		score = 50
		quality = 35
		tags = "FILE"

	strings:
		$file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=[^\x0d]*(powershell|cmd|certutil|mshta|wscript|cscript|rundll32|wmic|regsvr32|msbuild)(\.exe|)[^\x0d]{2,50}\x0d/ nocase
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		any of ($url*) and any of ($file*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
