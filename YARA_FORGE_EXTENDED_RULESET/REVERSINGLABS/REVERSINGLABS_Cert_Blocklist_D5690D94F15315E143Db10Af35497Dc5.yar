import "pe"

rule REVERSINGLABS_Cert_Blocklist_D5690D94F15315E143Db10Af35497Dc5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "324b2e2f-bad7-5ac4-864c-044d99fa01dc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12684-L12702"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4ac17d0f0e4ef2bb5f6cda8e7cb07a641d49c83465a0a80c46ff6e0e752d1847"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PET SERVICES d.o.o." and (pe.signatures[i].serial=="00:d5:69:0d:94:f1:53:15:e1:43:db:10:af:35:49:7d:c5" or pe.signatures[i].serial=="d5:69:0d:94:f1:53:15:e1:43:db:10:af:35:49:7d:c5") and 1576195200<=pe.signatures[i].not_after)
}
