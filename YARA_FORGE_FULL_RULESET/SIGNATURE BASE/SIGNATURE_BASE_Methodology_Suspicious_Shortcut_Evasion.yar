rule SIGNATURE_BASE_Methodology_Suspicious_Shortcut_Evasion : FILE
{
	meta:
		description = "Non-standard .URLs and evasion"
		author = "@itsreallynick (Nick Carr)"
		id = "36df4252-2575-5efa-88ce-17e68a349306"
		date = "2019-09-27"
		modified = "2023-12-05"
		reference = "https://twitter.com/DissectMalware/status/1176736510856634368"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L181-L198"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c4fafae6af3ed5cc2e83e30427107d1c42cc4bc86d5c6a60e26953a11847029f"
		score = 50
		quality = 35
		tags = "FILE"

	strings:
		$URI = /[\x0a\x0d](IconFile|(Base|)URL)[^\x0d=]+/ nocase
		$filetype_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$filetype_explicit = "[InternetShortcut]" nocase

	condition:
		any of ($filetype*) and $URI and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
