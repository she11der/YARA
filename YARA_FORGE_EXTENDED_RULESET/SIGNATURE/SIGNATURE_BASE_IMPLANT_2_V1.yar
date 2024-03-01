import "pe"

rule SIGNATURE_BASE_IMPLANT_2_V1 : FILE
{
	meta:
		description = "CORESHELL/SOURFACE Implant by APT28"
		author = "US CERT"
		id = "058266d4-8dc5-5a26-9bc6-4c55ac646e9b"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L126-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6708239ea43fd36a7c9431cd2c6c185c0d406d65c4a31374c5e96bdc3e53de43"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = { 8d ?? fa [2] e8 [2] FF FF C7 [2-5] 00 00 00 00 8D [2-5] 5? 6a 00 6a 01}

	condition:
		( uint16(0)==0x5A4D) and all of them
}
