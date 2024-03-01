import "pe"

rule REVERSINGLABS_Cert_Blocklist_E963F8983D21B4C1A69C66A9D37498E5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4cbc6cc9-1795-5d43-84a1-dd835d7ef349"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12480-L12498"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b7c715e28f003351d10ba53657e9e667b635a0e4433276d91d26f4482a61191d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Max Steinhard" and (pe.signatures[i].serial=="00:e9:63:f8:98:3d:21:b4:c1:a6:9c:66:a9:d3:74:98:e5" or pe.signatures[i].serial=="e9:63:f8:98:3d:21:b4:c1:a6:9c:66:a9:d3:74:98:e5") and 1656288000<=pe.signatures[i].not_after)
}
