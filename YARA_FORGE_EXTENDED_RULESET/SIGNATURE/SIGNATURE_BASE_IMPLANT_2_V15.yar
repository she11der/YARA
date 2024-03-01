import "pe"

rule SIGNATURE_BASE_IMPLANT_2_V15 : FILE
{
	meta:
		description = "CORESHELL/SOURFACE Implant by APT28"
		author = "US CERT"
		id = "9bdaebc1-86a0-5c21-b752-d69cdb70f082"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L295-L310"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fac61e80803941193c41ecf8b3fcbee21b5cc41542989ecd93542c32e87da983"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$XOR_LOOP1 = { 32 1C 02 33 D2 8B C7 89 5D E4 BB 06 00 00 00 F7 F3 }
		$XOR_LOOP2 = { 32 1C 02 8B C1 33 D2 B9 06 00 00 00 F7 F1 }
		$XOR_LOOP3 = { 02 C3 30 06 8B 5D F0 8D 41 FE 83 F8 06 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
