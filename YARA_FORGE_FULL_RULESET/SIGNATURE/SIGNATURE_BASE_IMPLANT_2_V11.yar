import "pe"

rule SIGNATURE_BASE_IMPLANT_2_V11 : FILE
{
	meta:
		description = "CORESHELL/SOURFACE Implant by APT28"
		author = "US CERT"
		id = "570d6996-ab16-556e-b790-e4c73d7bbffc"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L253-L267"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "72b9e4de0389df3a14f92660e91749dea4d31905eb7391163c3503bc953d661f"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = {55 8b ec 6a fe 68 [4] 68 [4] 64 A1 00 00 00 00 50 83 EC 0C 53
         56 57 A1 [4] 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 00 00 [8-14] 68
         [4] 6a 01 [1-2] FF 15 [4] FF 15 [4] 3D B7 00 00 00 75 27}

	condition:
		( uint16(0)==0x5A4D) and all of them
}
