import "pe"

rule SIGNATURE_BASE_TA17_318A_Success_Fail_Codes_Fallchill : FILE
{
	meta:
		description = "HiddenCobra FallChill - success_fail_codes"
		author = "US CERT"
		id = "f2390b03-238e-5ae6-af85-e5dd5790362f"
		date = "2017-11-15"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_ta17_318A.yar#L23-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "73f6b36554d83f7708e9468602e529c4865269d362ebeebf6b355ccf7c2a8686"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s0 = { 68 7a 34 12 00 }
		$s1 = { ba 7a 34 12 00 }
		$f0 = { 68 5c 34 12 00 }
		$f1 = { ba 5c 34 12 00 }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and (($s0 and $f0) or ($s1 and $f1))
}
