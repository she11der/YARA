import "pe"

rule SIGNATURE_BASE_IMPLANT_4_V13 : FILE
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		id = "e96a7d9f-1840-542f-9a9b-95e74377f234"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L1011-L1032"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "576c07c44105d2a38ca715d366f68058b2b3118f25e91d2d3e2d20e932fc9453"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$XMLDOM1 = {81 BF 33 29 36 7B D2 11 B2 0E 00 C0 4F 98 3E 60}
		$XMLDOM2 = {90 BF 33 29 36 7B D2 11 B2 0E 00 C0 4F 98 3E 60}
		$XMLPARSE = {8B 06 [0-2] 8D 55 ?C 52 FF 75 08 [0-2] 50 FF 91 04 01 00 00
         66 83 7D ?C FF 75 3? 8B 06 [0-2] 8D 55 F? 52 50 [0-2] FF 51 30 85 C0
         78 2?}
		$EXP1 = "DispatchCommand"
		$EXP2 = "DispatchEvent"
		$BDATA = {85 C0 74 1? 0F B7 4? 06 83 C? 28 [0-6] 72 ?? 33 C0 5F 5E 5B 5D
         C2 08 00 8B 4? 0? 8B 4? 0? 89 01 8B 4? 0C 03 [0-2] EB E?}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
