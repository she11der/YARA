import "pe"

rule REVERSINGLABS_Cert_Blocklist_149C12083C145E28155510Cfc19Db0Fe : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8d9b0b1c-df7c-560a-8d51-bc8738952457"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2898-L2914"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f616fc470e223d65ac4c984394a38d566265ab37829ff566012de0a1527396c2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "3rd Eye Solutions Ltd" and pe.signatures[i].serial=="14:9c:12:08:3c:14:5e:28:15:55:10:cf:c1:9d:b0:fe" and 1209340799<=pe.signatures[i].not_after)
}
