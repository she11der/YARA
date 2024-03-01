import "pe"

rule REVERSINGLABS_Cert_Blocklist_E3D5089D4B8F01Aadce2731062Fb0Cce : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "25df791f-1128-51f9-90da-9977262d00c7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7182-L7200"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7f10b86f156ccac695f480661dfea8bcc455477afd9575230c2f8510327d1996"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DEVELOP - Residence s. r. o." and (pe.signatures[i].serial=="00:e3:d5:08:9d:4b:8f:01:aa:dc:e2:73:10:62:fb:0c:ce" or pe.signatures[i].serial=="e3:d5:08:9d:4b:8f:01:aa:dc:e2:73:10:62:fb:0c:ce") and 1618358400<=pe.signatures[i].not_after)
}
