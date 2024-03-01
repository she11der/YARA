import "pe"

rule REVERSINGLABS_Cert_Blocklist_1895433Ee9E2Bd48619D75132262616F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d7bf59df-708c-5260-bc98-1a86b2c9c988"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11328-L11344"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f00a29ff5dddae40225ab62cb2d4b9dec1539ad58c8cd27d686480eecdb3e31d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Evetrans Ltd" and pe.signatures[i].serial=="18:95:43:3e:e9:e2:bd:48:61:9d:75:13:22:62:61:6f" and 1619789516<=pe.signatures[i].not_after)
}
