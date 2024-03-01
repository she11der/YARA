import "pe"

rule REVERSINGLABS_Cert_Blocklist_51Aead5A9Ab2D841B449Fa82De3A8A00 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c4909945-f2f1-53b2-b438-edf411fda7ed"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4950-L4966"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e53095aab9d6c2745125e8cd933334ebc2e51a9725714d31a46baa74b8e42ed9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Corsair Software Solution Inc." and pe.signatures[i].serial=="51:ae:ad:5a:9a:b2:d8:41:b4:49:fa:82:de:3a:8a:00" and 1501577475<=pe.signatures[i].not_after)
}
