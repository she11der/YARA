import "pe"

rule REVERSINGLABS_Cert_Blocklist_F8E8F6C92Ba666B0688A8Cacce9Acccf : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "909d0ce9-406c-539f-9d0e-d7ab1b277ee3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7162-L7180"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "aa419bc044be55d4c94481998be4e9c0310416740084eb8376842cf5416d78bf"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "5 th Dimension LTD Oy" and (pe.signatures[i].serial=="00:f8:e8:f6:c9:2b:a6:66:b0:68:8a:8c:ac:ce:9a:cc:cf" or pe.signatures[i].serial=="f8:e8:f6:c9:2b:a6:66:b0:68:8a:8c:ac:ce:9a:cc:cf") and 1618531200<=pe.signatures[i].not_after)
}
