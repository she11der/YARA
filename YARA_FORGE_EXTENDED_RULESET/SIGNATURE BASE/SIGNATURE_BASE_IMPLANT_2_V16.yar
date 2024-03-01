import "pe"

rule SIGNATURE_BASE_IMPLANT_2_V16 : FILE
{
	meta:
		description = "CORESHELL/SOURFACE Implant by APT28"
		author = "US CERT"
		id = "2c54a749-c80b-5010-97b6-b74c54fd3d07"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L312-L329"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "638cb66e5ff52ac5a1df0954969e7c54a3b25518228e4f8f344aafe6760985d2"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$OBF_FUNCT = { 0F B6 1C 0B 8D 34 08 8D 04 0A 0F AF D8 33 D2 8D 41 FF F7
         75 F8 8B 45 0C C1 EB 07 8D 79 01 32 1C 02 33 D2 8B C7 89 5D E4 BB 06
         00 00 00 F7 F3 8B 45 0C 8D 59 FE 02 5D FF 32 1C 02 8B C1 33 D2 B9 06
         00 00 00 F7 F1 8B 45 0C 8B CF 22 1C 02 8B 45 E4 8B 55 E0 02 C3 30 06
         8B 5D F0 8D 41 FE 83 F8 06 8B 45 DC 72 9A }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and $OBF_FUNCT
}
