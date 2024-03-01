import "pe"

rule REVERSINGLABS_Cert_Blocklist_351Fe2Efdc0Ac56A0C822Cf8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ac6b7c6d-781b-5c91-80fe-b822ee00ea7f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4326-L4342"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "46b87c3531e01ba150f056ec3270564426363ef8c58256eeedbcab247c7625e4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Logika OOO" and pe.signatures[i].serial=="35:1f:e2:ef:dc:0a:c5:6a:0c:82:2c:f8" and 1594976475<=pe.signatures[i].not_after)
}
