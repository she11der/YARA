import "pe"

rule SIGNATURE_BASE_IMPLANT_2_V10 : FILE
{
	meta:
		description = "CORESHELL/SOURFACE Implant by APT28"
		author = "US CERT"
		id = "cb88ae0c-19e2-590c-9c13-78ac1dcc8c9f"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L238-L251"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "62d47c1076b05bc9a531ef6e48f17f730932826b4b0f311887e3b14c639b937d"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF [6-8]
         48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01}

	condition:
		( uint16(0)==0x5A4D) and all of them
}
