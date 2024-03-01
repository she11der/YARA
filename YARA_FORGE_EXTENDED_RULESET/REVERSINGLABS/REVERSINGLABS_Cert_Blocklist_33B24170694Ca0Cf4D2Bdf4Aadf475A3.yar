import "pe"

rule REVERSINGLABS_Cert_Blocklist_33B24170694Ca0Cf4D2Bdf4Aadf475A3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c02d7aaf-e88a-5aba-a8ee-db34562e53b1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14058-L14074"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "795bcb46b41ded084e4d12d98e335748ec1db3e0abbbb2d933e819d955075138"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="33:b2:41:70:69:4c:a0:cf:4d:2b:df:4a:ad:f4:75:a3" and 1474934400<=pe.signatures[i].not_after)
}
