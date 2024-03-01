import "pe"

rule REVERSINGLABS_Cert_Blocklist_1A35Acce5B0C77206B1C3Dc2A6A2417C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0e42ffb8-07f2-55e4-977d-7760e923d76d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L675-L691"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ce161fdd511e0efa042516ead09c6ab5f8dcf54f2087cdccbfed8e7cdfbd25b2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "cd ingegneri associati srl" and pe.signatures[i].serial=="1a:35:ac:ce:5b:0c:77:20:6b:1c:3d:c2:a6:a2:41:7c" and 1166054399<=pe.signatures[i].not_after)
}
