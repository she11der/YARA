import "pe"

rule REVERSINGLABS_Cert_Blocklist_05F70A557Afd4A443F44D0Baf0Bc8C60 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9ce5b6c7-fede-508f-a7d0-f9d0b8838645"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15918-L15934"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3945f515b65ca3ffb6c2b64c884bb2790d703a277e1a5ba128c81bc63ed20a25"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="05:f7:0a:55:7a:fd:4a:44:3f:44:d0:ba:f0:bc:8c:60" and 1477440000<=pe.signatures[i].not_after)
}
