import "pe"

rule REVERSINGLABS_Cert_Blocklist_25F222Ab2613Dc4270B2Aabc2519A101 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4458df2d-82c2-5377-9746-101c2de52913"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16872-L16888"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2c6673f6821c4ba11fc015cf3e9edefeb7c45209bc9dcd18501c4681444a9b9e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aeroscan TOV" and pe.signatures[i].serial=="25:f2:22:ab:26:13:dc:42:70:b2:aa:bc:25:19:a1:01" and 1445299200<=pe.signatures[i].not_after)
}
