import "pe"

rule SIGNATURE_BASE_SUSP_Unsigned_Googleupdate : FILE
{
	meta:
		description = "Detects suspicious unsigned GoogleUpdate.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2575b882-3526-5c42-9d50-83fb0b7df3f5"
		date = "2019-08-05"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_google_anomaly.yar#L3-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5e333ac773927e2ed1f6aa4d6bbcb63d67bcc8d18d732a84bb68cb503469b247"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "5aa84aa5c90ec34b7f7d75eb350349ae3aa5060f3ad6dd0520e851626e9f8354"

	strings:
		$ac1 = { 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C
               00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65
               00 00 00 47 00 6F 00 6F 00 67 00 6C 00 65 00 55
               00 70 00 64 00 61 00 74 00 65 00 2E 00 65 00 78
               00 65 }

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and $ac1 and pe.number_of_signatures<1
}
