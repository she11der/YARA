import "pe"

rule SIGNATURE_BASE_IMPLANT_6_V6 : FILE
{
	meta:
		description = "Sednit / EVILTOSS Implant by APT28"
		author = "US CERT"
		id = "89cc3764-d60c-5cbd-af32-a90d8b3400d7"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L1329-L1343"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "77b5f95cd897c82c200ee6fa3970824adccfd7c56639d92361095f919781d731"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$Init1_fun = {68 10 27 00 00 FF 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 6A FF 50
         FF 15 ?? ?? ?? ?? 33 C0 C3}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
