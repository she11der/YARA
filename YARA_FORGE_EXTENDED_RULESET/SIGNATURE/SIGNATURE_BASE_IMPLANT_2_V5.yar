import "pe"

rule SIGNATURE_BASE_IMPLANT_2_V5 : FILE
{
	meta:
		description = "CORESHELL/SOURFACE Implant by APT28"
		author = "US CERT"
		id = "0e787116-d7f5-5a72-9aba-d4e6cb35bc8d"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L157-L171"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b0929b808f62e3c59c0afbe959ebf67a3a985e0a0a72bcb112c9693a98351555"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = {48 83 [2] 48 89 [3] c7 44 [6] 4c 8d 05 [3] 00 BA 01 00 00 00 33
         C9 ff 15 [2] 00 00 ff 15 [2] 00 00 3D B7 00 00 00 75 ?? 48 8D 15 ?? 00
         00 00 48 8B CC E8}

	condition:
		( uint16(0)==0x5A4D) and all of them
}
