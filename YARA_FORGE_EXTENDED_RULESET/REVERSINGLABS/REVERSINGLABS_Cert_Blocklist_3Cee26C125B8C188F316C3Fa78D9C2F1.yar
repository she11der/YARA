import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Cee26C125B8C188F316C3Fa78D9C2F1 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "79989b9b-60e4-577d-97e2-cb447c38baf3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8150-L8166"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5c64f8e40c31822ce8d2e34f96ccc977085e429f0c068a5f6b44099117837de1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bitubit LLC" and pe.signatures[i].serial=="3c:ee:26:c1:25:b8:c1:88:f3:16:c3:fa:78:d9:c2:f1" and 1606435200<=pe.signatures[i].not_after)
}
