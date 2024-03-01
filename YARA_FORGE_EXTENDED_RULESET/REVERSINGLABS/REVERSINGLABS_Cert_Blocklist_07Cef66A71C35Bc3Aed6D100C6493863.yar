import "pe"

rule REVERSINGLABS_Cert_Blocklist_07Cef66A71C35Bc3Aed6D100C6493863 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9c16c370-a382-54f7-ba2e-3b738740966f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6122-L6138"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e741fc13fe4d03b145ed1d86e738b415a7260eae5b0908c6991c9ea9896f14cf"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fubon Technologies Ltd" and pe.signatures[i].serial=="07:ce:f6:6a:71:c3:5b:c3:ae:d6:d1:00:c6:49:38:63" and 1602740890<=pe.signatures[i].not_after)
}
