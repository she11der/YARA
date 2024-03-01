import "pe"

rule REVERSINGLABS_Cert_Blocklist_734819463C1195Bd6E135Ce4D5Bf49Bc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f7dd21fa-1501-50b2-bd9c-c33cfd932a6b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10200-L10216"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a63c05cca23b61ba6eabda2b60c617b966a2669fd3a0da30354792e5c1ae2140"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "videoalarm s. r. o." and pe.signatures[i].serial=="73:48:19:46:3c:11:95:bd:6e:13:5c:e4:d5:bf:49:bc" and 1637884800<=pe.signatures[i].not_after)
}
