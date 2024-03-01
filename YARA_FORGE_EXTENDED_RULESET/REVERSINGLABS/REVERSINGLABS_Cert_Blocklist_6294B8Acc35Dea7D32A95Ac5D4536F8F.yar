import "pe"

rule REVERSINGLABS_Cert_Blocklist_6294B8Acc35Dea7D32A95Ac5D4536F8F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bc380123-20fc-55de-ad1c-4f13ac173cc9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15078-L15094"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ac92ff8e533121071a620ca5280ae66629576f9c4af9831ddac5bb487e4348af"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE9\\x87\\x8D\\xE5\\xBA\\x86\\xE6\\x8E\\xA2\\xE9\\x95\\xBF\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="62:94:b8:ac:c3:5d:ea:7d:32:a9:5a:c5:d4:53:6f:8f" and 1517443200<=pe.signatures[i].not_after)
}
