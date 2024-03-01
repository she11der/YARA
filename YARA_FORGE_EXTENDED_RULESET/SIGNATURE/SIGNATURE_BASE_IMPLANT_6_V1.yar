import "pe"

rule SIGNATURE_BASE_IMPLANT_6_V1 : FILE
{
	meta:
		description = "Sednit / EVILTOSS Implant by APT28"
		author = "US CERT"
		id = "0554ec8e-f45d-5afc-8874-dc8adfac5cdf"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L1227-L1243"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c60402a029034545df302485c14e9485f806f2bc7d5fd759e84d1ecba9854837"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = "dll.dll" wide ascii
		$STR2 = "Init1" wide ascii
		$STR3 = "netui.dll" wide ascii

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
