import "pe"

rule REVERSINGLABS_Cert_Blocklist_A758504E7971869D0Aec2775Fffa03D5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cc8c0cca-1848-5a5e-a421-c5ecdea6ba53"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9038-L9056"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "dcb1ac4c7dcbebd0a432515da82e4a97be6c6c2a54f9d642aa8c1a2bcbdce5de"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Amcert LLC" and (pe.signatures[i].serial=="00:a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5" or pe.signatures[i].serial=="a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5") and 1623628800<=pe.signatures[i].not_after)
}
