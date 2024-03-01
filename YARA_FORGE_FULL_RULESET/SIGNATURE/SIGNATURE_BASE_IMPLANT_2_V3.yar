import "pe"

rule SIGNATURE_BASE_IMPLANT_2_V3 : FILE
{
	meta:
		description = "CORESHELL/SOURFACE Implant by APT28"
		author = "US CERT"
		id = "747e4f76-b9c4-5988-90ae-b450548b1b82"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L140-L155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ebfedcec6f22d802a9980ad533f21e90b77fe929a813850be1b25304d3973c3b"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = {C1 EB 07 8D ?? 01 32 1C ?? 33 D2 }
		$STR2 = {2B ?? 83 ?? 06 0F 83 ?? 00 00 00 EB 02 33 }
		$STR3 = {89 ?? ?? 89 ?? ?? 89 55 ?? 89 45 ?? 3B ?? 0F 83 ?? 00 00 00 8D
         ?? ?? 8D ?? ?? FE }

	condition:
		( uint16(0)==0x5A4D) and any of them
}
