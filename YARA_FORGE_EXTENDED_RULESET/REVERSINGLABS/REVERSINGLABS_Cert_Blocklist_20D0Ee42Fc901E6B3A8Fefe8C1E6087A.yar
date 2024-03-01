import "pe"

rule REVERSINGLABS_Cert_Blocklist_20D0Ee42Fc901E6B3A8Fefe8C1E6087A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Sakula malware."
		author = "ReversingLabs"
		id = "ba37919a-584b-5ff7-b4d5-5b711cc87b1f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2140-L2156"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2225302de1e8fe9f2ad064e19b2b1d9faf90c7cafbebff6ddd0921bf57c5f9e6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SJ SYSTEM" and pe.signatures[i].serial=="20:d0:ee:42:fc:90:1e:6b:3a:8f:ef:e8:c1:e6:08:7a" and 1391299199<=pe.signatures[i].not_after)
}
