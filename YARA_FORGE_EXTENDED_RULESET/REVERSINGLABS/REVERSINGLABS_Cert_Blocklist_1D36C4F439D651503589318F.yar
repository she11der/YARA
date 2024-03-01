import "pe"

rule REVERSINGLABS_Cert_Blocklist_1D36C4F439D651503589318F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f72b8e2c-b799-5aec-a69a-e42cdb3e2ae1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10680-L10696"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "73dc3c01041d50100a8d5519afe1a80f470c30175f9ad1bf76ac287ac199a959"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REDWOOD MARKETING SOLUTIONS INC." and pe.signatures[i].serial=="1d:36:c4:f4:39:d6:51:50:35:89:31:8f" and 1651518469<=pe.signatures[i].not_after)
}
