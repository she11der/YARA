import "pe"

rule SIGNATURE_BASE_IMPLANT_9_V1 : FILE
{
	meta:
		description = "Onion Duke Implant by APT29"
		author = "US CERT"
		id = "5460ff29-681b-5d11-a6ba-5f294e8577e6"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L1431-L1447"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "76704410af27060131ee4a5f46601b8badbf822d8084511145078607db715651"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = { 8B 03 8A 54 01 03 32 55 FF 41 88 54 39 FF 3B CE 72 EE }
		$STR2 = { 8B C8 83 E1 03 8A 54 19 08 8B 4D 08 32 54 01 04 40 88 54 38 FF
         3B C6 72 E7 }
		$STR3 = { 8B 55 F8 8B C8 83 E1 03 8A 4C 11 08 8B 55 FC 32 0C 10 8B 17 88
         4C 02 04 40 3B 06 72 E3 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)) and all of them
}
