import "pe"

rule REVERSINGLABS_Cert_Blocklist_028D50Ae0C554B49148E82Db5B1C2699 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "76ccda8a-bdea-5db2-a3a4-11292bfb3c95"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3978-L3994"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e3cc0066cad56d78a3f42e092befa3b0855b2ed33c8465c5ecbb19fec082d35e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VAS CO PTY LTD" and pe.signatures[i].serial=="02:8d:50:ae:0c:55:4b:49:14:8e:82:db:5b:1c:26:99" and 1579478400<=pe.signatures[i].not_after)
}
