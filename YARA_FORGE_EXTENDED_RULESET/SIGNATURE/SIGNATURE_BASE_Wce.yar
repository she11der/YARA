import "pe"

rule SIGNATURE_BASE_Wce
{
	meta:
		description = "wce"
		author = "Benjamin DELPY (gentilkiwi)"
		id = "857981ee-3f57-580b-8bfd-8d2109298e27"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mimikatz.yar#L76-L89"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "a16db99dcaaf1b6c33a738aab4f4d3812366258bc2f6dd32250ee1b1a0616f1c"
		score = 75
		quality = 85
		tags = ""
		tool_author = "Hernan Ochoa (hernano)"

	strings:
		$hex_legacy = { 8b ff 55 8b ec 6a 00 ff 75 0c ff 75 08 e8 [0-3] 5d c2 08 00 }
		$hex_x86 = { 8d 45 f0 50 8d 45 f8 50 8d 45 e8 50 6a 00 8d 45 fc 50 [0-8] 50 72 69 6d 61 72 79 00 }
		$hex_x64 = { ff f3 48 83 ec 30 48 8b d9 48 8d 15 [0-16] 50 72 69 6d 61 72 79 00 }

	condition:
		any of them
}
