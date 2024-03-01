import "pe"

rule SIGNATURE_BASE_IMPLANT_2_V6 : FILE
{
	meta:
		description = "CORESHELL/SOURFACE Implant by APT28"
		author = "US CERT"
		id = "ffadb02f-6311-567d-900b-c8a9ed172ab4"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L173-L186"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "93ce725a8af03d6f08eafe99ff3984e03a434b1f0071c6dbe560bafc3eefb576"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = { e8 [2] ff ff 8b [0-6] 00 04 00 00 7F ?? [1-2] 00 02 00 00 7F
         ?? [1-2] 00 01 00 00 7F ?? [1-2] 80 00 00 00 7F ?? 83 ?? 40 7F}

	condition:
		( uint16(0)==0x5A4D) and all of them
}
