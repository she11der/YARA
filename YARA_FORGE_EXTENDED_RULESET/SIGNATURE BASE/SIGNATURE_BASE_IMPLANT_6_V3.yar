import "pe"

rule SIGNATURE_BASE_IMPLANT_6_V3 : FILE
{
	meta:
		description = "Sednit / EVILTOSS Implant by APT28"
		author = "US CERT"
		id = "db090bc5-a90f-5b66-8fcb-29b423dddbf7"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L1260-L1275"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "833a6a3a4ff8ca43d4cf8053bfd1da49df96d9833dd3fe0f3ffbf6ce6c114681"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$deob_func = { 8D 46 01 02 D1 83 E0 07 8A 04 38 F6 EA 8B D6 83 E2 07 0A
         04 3A 33 D2 8A 54 37 FE 03 D3 03 D1 D3 EA 32 C2 8D 56 FF 83 E2 07 8A
         1C 3A 8A 14 2E 32 C3 32 D0 41 88 14 2E 46 83 FE 0A 7C ?? }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
