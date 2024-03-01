import "pe"

rule REVERSINGLABS_Cert_Blocklist_15Da61D7E1A631803431561674Fb9B90 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "07518dc2-bd6c-5a4c-b537-68f5a462cdc2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8566-L8582"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "75d2c3b47fe9c863812f2c98fc565af9050b909a03528e2ea4a96542a3ec0c0d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JAY DANCE STUDIO d.o.o." and pe.signatures[i].serial=="15:da:61:d7:e1:a6:31:80:34:31:56:16:74:fb:9b:90" and 1610668800<=pe.signatures[i].not_after)
}
