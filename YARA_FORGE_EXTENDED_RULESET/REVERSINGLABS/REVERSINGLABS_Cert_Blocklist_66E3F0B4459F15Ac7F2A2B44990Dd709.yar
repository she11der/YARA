import "pe"

rule REVERSINGLABS_Cert_Blocklist_66E3F0B4459F15Ac7F2A2B44990Dd709 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2fc1303f-e559-59ba-a1b9-b74a154d8805"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16230-L16246"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a563f1485ae8887c46f45d1366f676894c7db55954671825b37372f786ce0d3d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KOG Co., Ltd." and pe.signatures[i].serial=="66:e3:f0:b4:45:9f:15:ac:7f:2a:2b:44:99:0d:d7:09" and 1320288125<=pe.signatures[i].not_after)
}
