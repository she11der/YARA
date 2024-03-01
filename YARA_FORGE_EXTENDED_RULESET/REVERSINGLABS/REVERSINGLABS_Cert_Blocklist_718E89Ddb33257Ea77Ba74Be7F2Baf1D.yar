import "pe"

rule REVERSINGLABS_Cert_Blocklist_718E89Ddb33257Ea77Ba74Be7F2Baf1D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d173c2b2-2b76-521a-aac1-ae69fdf5b16b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9612-L9628"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2f0defa1e1d905d937677e96f2a0955d9737f6976596932cc093fdecfea3fdb0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Trap Capital ApS" and pe.signatures[i].serial=="71:8e:89:dd:b3:32:57:ea:77:ba:74:be:7f:2b:af:1d" and 1635462927<=pe.signatures[i].not_after)
}
