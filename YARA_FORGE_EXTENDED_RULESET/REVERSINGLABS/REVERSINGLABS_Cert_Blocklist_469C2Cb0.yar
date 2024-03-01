import "pe"

rule REVERSINGLABS_Cert_Blocklist_469C2Cb0 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "dd19b988-747d-55b9-825b-2ada1ca83691"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L945-L961"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "67ff84475cbe231f97daa3ce623689e7936db8e56be562778f8a4c1ebf7bf316"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DigiNotar Services 1024 CA" and pe.signatures[i].serial=="46:9c:2c:b0" and 1308182400<=pe.signatures[i].not_after)
}
