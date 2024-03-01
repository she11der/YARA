import "pe"

rule SIGNATURE_BASE_IMPLANT_1_V3 : FILE
{
	meta:
		description = "Downrage Implant by APT28"
		author = "US CERT"
		id = "517133d2-813d-5f44-84c2-a53c62d7a688"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L45-L58"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e418620b45bc11804eae24db3cba8421758c214fc9f660a17761bbf3395ad744"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$rol7encode = { 0F B7 C9 C1 C0 07 83 C2 02 33 C1 0F B7 0A 47 66 85 C9 75 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
