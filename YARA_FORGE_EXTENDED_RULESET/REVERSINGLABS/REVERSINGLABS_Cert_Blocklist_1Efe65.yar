import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Efe65 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e402e3b4-a598-504d-85b8-8c1994cb51fc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14458-L14474"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f849b6899b6766807cfddf99ecb809fe923f35f04de09b62235da352ce6e6e24"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Software Plugin Ltd." and pe.signatures[i].serial=="1e:fe:65" and 1063224491<=pe.signatures[i].not_after)
}
