import "pe"

rule REVERSINGLABS_Cert_Blocklist_4Fbcaa289Ba925B4E247809B6B028202 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d0c4c6c0-d8e3-5efc-a87b-01d1f98a2c18"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3922-L3938"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c41a4f9ccda54b9735313edf9042b831e6eaca149c089f74a823cee6719e1064"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kimjac ApS" and pe.signatures[i].serial=="4f:bc:aa:28:9b:a9:25:b4:e2:47:80:9b:6b:02:82:02" and 1588227220<=pe.signatures[i].not_after)
}
