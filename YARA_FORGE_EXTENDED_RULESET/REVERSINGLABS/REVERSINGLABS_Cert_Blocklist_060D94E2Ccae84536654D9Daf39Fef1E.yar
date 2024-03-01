import "pe"

rule REVERSINGLABS_Cert_Blocklist_060D94E2Ccae84536654D9Daf39Fef1E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ac5d29ef-fd52-536b-bcbc-44433dda8a21"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9402-L9418"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "49000f3a3ce1ad9aef87162d7527b8f062e0aa12276b82c7335f0ccc14b7d38a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HasCred ApS" and pe.signatures[i].serial=="06:0d:94:e2:cc:ae:84:53:66:54:d9:da:f3:9f:ef:1e" and 1627948800<=pe.signatures[i].not_after)
}
