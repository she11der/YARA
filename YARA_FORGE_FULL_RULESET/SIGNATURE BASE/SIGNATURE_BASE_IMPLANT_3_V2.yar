import "pe"

rule SIGNATURE_BASE_IMPLANT_3_V2 : FILE
{
	meta:
		description = "X-Agent/CHOPSTICK Implant by APT28"
		author = "US CERT"
		id = "349c65cf-547f-5837-af71-f9721e029b74"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L444-L464"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0a658888dcc7b7f4620f08449c6ec492756750e64f15b048f7cdee7de4fc0479"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$base_key_moved = {C7 45 ?? 3B C6 73 0F C7 45 ?? 8B 07 85 C0 C7 45 ?? 74
         02 FF D0 C7 45 ?? 83 C7 04 3B C7 45 ?? FE 72 F1 5F C7 45 ?? 5E C3 8B
         FF C7 45 ?? 56 B8 D8 78 C7 45 ?? 75 07 50 E8 C7 45 ?? B1 D1 FF FF C7
         45 ?? 59 5D C3 8B C7 45 ?? FF 55 8B EC C7 45 ?? 83 EC 10 A1 66 C7 45
         ?? 33 35}
		$base_key_b_array = {3B C6 73 0F 8B 07 85 C0 74 02 FF D0 83 C7 04 3B FE
         72 F1 5F 5E C3 8B FF 56 B8 D8 78 75 07 50 E8 B1 D1 FF FF 59 5D C3 8B
         FF 55 8B EC 83 EC 10 A1 33 35 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and any of them
}
