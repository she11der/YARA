import "pe"

rule REVERSINGLABS_Cert_Blocklist_1121Ed568764E75Be35574448Feadefcd3Bc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "44fa007f-f5f7-5001-8b92-eb4a657ea756"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L351-L367"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3316a2536920c5aa9dd627cec7678e6fe33c722b4830dd740009c20dd013c9ab"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FRINORTE COMERCIO DE PECAS E SERVICOS LTDA - ME" and pe.signatures[i].serial=="11:21:ed:56:87:64:e7:5b:e3:55:74:44:8f:ea:de:fc:d3:bc" and 1385337599<=pe.signatures[i].not_after)
}
