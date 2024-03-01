import "pe"

rule REVERSINGLABS_Cert_Blocklist_0813Ee9B7B9D7C46001D6Bc8784Df1Dd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0915fae0-ac6f-5a92-ab44-80f840fd5061"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L729-L745"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1a25a2f25fa8d5075113cbafb73e80e741268d6b2f9e629fd54ffca9e82409b0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Les Garcons s'habillent" and pe.signatures[i].serial=="08:13:ee:9b:7b:9d:7c:46:00:1d:6b:c8:78:4d:f1:dd" and 1334707199<=pe.signatures[i].not_after)
}
