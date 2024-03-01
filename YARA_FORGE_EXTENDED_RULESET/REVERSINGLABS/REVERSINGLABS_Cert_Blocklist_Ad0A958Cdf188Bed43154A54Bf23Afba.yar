import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ad0A958Cdf188Bed43154A54Bf23Afba : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "183d9d02-885b-5f2f-b455-dd72af7bc5a6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8130-L8148"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "07e53e59f90aa3cd3a98dbca2627672606f6c6f8f3bda8456e32122463729c4b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RHM Ltd" and (pe.signatures[i].serial=="00:ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba" or pe.signatures[i].serial=="ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba") and 1612915200<=pe.signatures[i].not_after)
}
