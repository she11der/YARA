import "pe"

rule SIGNATURE_BASE_IMPLANT_6_V2 : FILE
{
	meta:
		description = "Sednit / EVILTOSS Implant by APT28"
		author = "US CERT"
		id = "59bfbef2-ff0e-59df-9d08-15001cec8ecf"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L1245-L1258"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7e81e8bcc305b9b7166db85d81278c96edf232bf60040ef15a2376f204ca3046"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$obf_func = { 8B 45 F8 6A 07 03 C7 33 D2 89 45 E8 8D 47 01 5B 02 4D 0F F7 F3 6A 07 8A 04 32 33 D2 F6 E9 8A C8 8B C7 F7 F3 8A 44 3E FE 02 45 FC 02 0C 32 B2 03 F6 EA 8A D8 8D 47 FF 33 D2 5F F7 F7 02 5D 14 8B 45 E8 8B 7D F4 C0 E3 06 02 1C 32 32 CB 30 08 8B 4D 14 41 47 83 FF 09 89 4D 14 89 7D F4 72 A1 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
