import "pe"

rule REVERSINGLABS_Cert_Blocklist_06Ce209477F1Ac19A2049Bdc5846A831 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "21c16e2c-bc0c-5e1d-bc44-6d7c4afc34cb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16176-L16192"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "24474c4033a8cad1690160da64b75a1eec570f56e830967256c19574bde59384"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Select'Assistance Pro" and pe.signatures[i].serial=="06:ce:20:94:77:f1:ac:19:a2:04:9b:dc:58:46:a8:31" and 1426710344<=pe.signatures[i].not_after)
}
