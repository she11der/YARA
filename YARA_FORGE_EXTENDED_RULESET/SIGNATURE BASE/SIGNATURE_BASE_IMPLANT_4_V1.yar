import "pe"

rule SIGNATURE_BASE_IMPLANT_4_V1 : FILE
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		id = "be4d222f-009f-5dde-93da-376626a77263"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L487-L503"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "51135d9fe62f5fd1fb7ef6c386dcdd86525dd469064662c2314cfee6e952d6ec"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = {55 8B EC 81 EC 54 01 00 00 83 65 D4 00 C6 45 D8 61 C6 45 D9 64
         C6 45 DA 76 C6 45 DB 61 C6 45 DC 70 C6 45 DD 69 C6 45 DE 33 C6 45 DF
         32 C6 45 E0 2EE9 ?? ?? ?? ??}
		$STR2 = {C7 45 EC 5A 00 00 00 C7 45 E0
            46 00 00 00 C7 45 E8 5A 00 00 00 C7 45 E4 46 00 00 00}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and 1 of them
}
