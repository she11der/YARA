import "pe"

rule SIGNATURE_BASE_IMPLANT_6_V5 : FILE
{
	meta:
		description = "Sednit / EVILTOSS Implant by APT28"
		author = "US CERT"
		id = "d035eaff-8c2a-53a2-b629-6448b2bcc9f6"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L1293-L1327"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b3ba650818ddbc58ce272ae4851ae3151a8cf1c9cc6f8e234a50b52c95d951fe"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = { 83 EC 18 8B 4C 24 24 B8 AB AA AA AA F7 E1 8B 44 24 20 53 55 8B
         EA 8D 14 08 B8 AB AA AA AA 89 54 24 1C F7 E2 56 8B F2 C1 ED 02 8B DD
         57 8B 7C 24 38 89 6C 24 1C C1 EE 02 3B DE 89 5C 24 18 89 74 24 20 0F
         83 CF 00 00 00 8D 14 5B 8D 44 12 FE 89 44 24 10 3B DD 0F 85 CF 00 00
         00 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B CA 83 F9 06 89 4C 24 38 0F 83
         86 00 00 00 8A C3 B2 06 F6 EA 8B 54 24 10 88 44 24 30 8B 44 24 2C 8D
         71 02 03 D0 89 54 24 14 8B 54 24 10 33 C0 8A 44 37 FE 03 D6 8B D8 8D
         46 FF 0F AF DA 33 D2 BD 06 00 00 00 F7 F5 C1 EB 07 8A 04 3A 33 D2 32
         D8 8D 46 01 F7 F5 8A 44 24 30 02 C1 8A 0C 3A 33 D2 32 C8 8B C6 F7 F5
         8A 04 3A 22 C8 8B 44 24 14 02 D9 8A 0C 30 32 CB 88 0C 30 8B 4C 24 38
         41 46 83 FE 08 89 4C 24 38 72 A1 8B 5C 24 18 8B 6C 24 1C 8B 74 24 20
         8B 4C 24 10 43 83 C1 06 3B DE 89 4C 24 10 8B 4C 24 34 89 5C 24 18 0F
         82 3C FF FF FF 3B DD 75 1A 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B CA EB
         0D 33 C9 89 4C 24 38 E9 40 FF FF FF 33 C9 8B 44 24 24 33 D2 BE 06 00
         00 00 89 4C 24 38 F7 F6 3B CA 89 54 24 24 0F 83 95 00 00 00 8A C3 B2
         06 F6 EA 8D 1C 5B 88 44 24 30 8B 44 24 2C 8D 71 02 D1 E3 89 5C 24 34
         8D 54 03 FE 89 54 24 14 EB 04 8B 5C 24 34 33 C0 BD 06 00 00 00 8A 44
         3E FE 8B D0 8D 44 1E FE 0F AF D0 C1 EA 07 89 54 24 2C 8D 46 FF 33 D2
         BB 06 00 00 00 F7 F3 8B 5C 24 2C 8A 04 3A 33 D2 32 D8 8D 46 01 F7 F5
         8A 44 24 30 02 C1 8A 0C 3A 33 D2 32 C8 8B C6 F7 F5 8A 04 3A 22 C8 8B
         44 24 14 02 D9 8A 0C 06 32 CB 88 0C 06 8B 4C 24 38 8B 44 24 24 41 46
         3B C8 89 4C 24 38 72 8F 5F 5E 5D 5B 83 C4 18 C2 10 00 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
