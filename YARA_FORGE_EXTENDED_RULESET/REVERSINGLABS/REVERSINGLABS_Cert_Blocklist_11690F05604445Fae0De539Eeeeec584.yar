import "pe"

rule REVERSINGLABS_Cert_Blocklist_11690F05604445Fae0De539Eeeeec584 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e6513bd1-2524-5baa-8484-b7e0f2f0c02a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2596-L2612"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b66257f562f698559910eb9576f8fdf0ce3a750cc0a96a27e2ec1a18872ad13f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tera information Technology co.Ltd" and pe.signatures[i].serial=="11:69:0f:05:60:44:45:fa:e0:de:53:9e:ee:ee:c5:84" and 1294703999<=pe.signatures[i].not_after)
}
