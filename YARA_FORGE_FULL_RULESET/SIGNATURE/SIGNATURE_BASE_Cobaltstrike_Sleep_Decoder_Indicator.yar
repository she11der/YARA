rule SIGNATURE_BASE_Cobaltstrike_Sleep_Decoder_Indicator
{
	meta:
		description = "Detects CobaltStrike sleep_mask decoder"
		author = "yara@s3c.za.net"
		id = "d5b53d68-55f9-5837-9b0c-e7be2f3bd072"
		date = "2021-07-19"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cobaltstrike_evasive.yar#L16-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f3243c326df18edbd15c2d9120379588e61709efb9295b9584c0565c04ee38a5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$sleep_decoder = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 4C 8B 51 08 41 8B F0 48 8B EA 48 8B D9 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 }

	condition:
		$sleep_decoder
}
