import "pe"

rule REVERSINGLABS_Cert_Blocklist_0939C2Bad859C0432E8E98A6C0162C02 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5dba4570-51d8-5c23-85a5-5de9a048793f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9002-L9018"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3c48241e52e58600bfa0385742831dba59d9cbd959cd6853fe8e030f5df79c23"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Activ Expeditions ApS" and pe.signatures[i].serial=="09:39:c2:ba:d8:59:c0:43:2e:8e:98:a6:c0:16:2c:02" and 1615939200<=pe.signatures[i].not_after)
}
