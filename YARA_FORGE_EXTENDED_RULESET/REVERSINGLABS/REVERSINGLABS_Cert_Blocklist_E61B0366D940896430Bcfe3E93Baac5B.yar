import "pe"

rule REVERSINGLABS_Cert_Blocklist_E61B0366D940896430Bcfe3E93Baac5B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "24eb38c1-48a5-5d9b-a42d-345c4fda6c36"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15058-L15076"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1b1fd0c2237446ab22c7359d1e89d822a4b9b6ad345447740154d7d52635c2ea"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TRANS LTD" and (pe.signatures[i].serial=="00:e6:1b:03:66:d9:40:89:64:30:bc:fe:3e:93:ba:ac:5b" or pe.signatures[i].serial=="e6:1b:03:66:d9:40:89:64:30:bc:fe:3e:93:ba:ac:5b") and 1528156800<=pe.signatures[i].not_after)
}
