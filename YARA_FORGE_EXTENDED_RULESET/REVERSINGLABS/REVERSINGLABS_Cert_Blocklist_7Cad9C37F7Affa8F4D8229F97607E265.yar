import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Cad9C37F7Affa8F4D8229F97607E265 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dae6b474-e4f0-5c73-b32e-d2680f508799"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14094-L14110"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0f88989c64bece23e7eccf8022e038fdd9c360766de71268cf71616f74adc56c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Funbit" and pe.signatures[i].serial=="7c:ad:9c:37:f7:af:fa:8f:4d:82:29:f9:76:07:e2:65" and 1122508800<=pe.signatures[i].not_after)
}
