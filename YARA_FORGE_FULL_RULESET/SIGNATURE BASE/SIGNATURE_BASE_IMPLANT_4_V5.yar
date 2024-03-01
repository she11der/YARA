import "pe"

rule SIGNATURE_BASE_IMPLANT_4_V5 : FILE
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		id = "d203f3c6-4e86-5632-ad5d-61763ee59bbe"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L824-L838"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9d4233ccf148919d0ad0be726b9dfa9e26a9afcebb7b26fa4db4c3da8c46d13e"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$GEN_HASH = {0F BE C9 C1 C0 07 33 C1}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
