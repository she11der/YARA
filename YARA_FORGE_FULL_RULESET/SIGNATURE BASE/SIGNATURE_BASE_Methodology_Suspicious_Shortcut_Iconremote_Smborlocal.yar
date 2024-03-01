rule SIGNATURE_BASE_Methodology_Suspicious_Shortcut_Iconremote_Smborlocal : FILE
{
	meta:
		description = "This is the syntax used for NTLM hash stealing via Responder - https://www.securify.nl/nl/blog/SFY20180501/living-off-the-land_-stealing-netntlm-hashes.html"
		author = "@itsreallynick (Nick Carr)"
		id = "9362ce46-265c-5215-bee1-3d784d0cb928"
		date = "2019-09-27"
		modified = "2023-12-05"
		reference = "https://twitter.com/ItsReallyNick/status/1176241449148588032"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_url_persitence.yar#L61-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8c49908c7f52ebcd512ff2dc8c40392767769130b9d39abb9d5fc9e130edb65c"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$icon = "IconFile=file://" nocase
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		$icon and any of ($url*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
