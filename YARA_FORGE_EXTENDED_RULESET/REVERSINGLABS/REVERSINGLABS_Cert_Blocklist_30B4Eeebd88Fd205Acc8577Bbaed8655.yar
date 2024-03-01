import "pe"

rule REVERSINGLABS_Cert_Blocklist_30B4Eeebd88Fd205Acc8577Bbaed8655 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "27c60ade-41e1-5ba4-be8d-275edc01b5ba"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10606-L10622"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "673ec5a1cacb9a7be101a4a533baf5a1eab4e6dd8721c69e56636701c5303c72"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Enforcer Srl" and pe.signatures[i].serial=="30:b4:ee:eb:d8:8f:d2:05:ac:c8:57:7b:ba:ed:86:55" and 1646179200<=pe.signatures[i].not_after)
}
