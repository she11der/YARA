import "pe"

rule REVERSINGLABS_Cert_Blocklist_58A541D50F9E2Fab4380C6A2Ed433B82 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "19a26581-5c94-5c8d-8e3e-b2ef1d770968"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1362-L1378"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "69ddc58b6fec159d6eded8c78237a6a0626b1aedb58b0c9867b758fd09db46ad"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Adobe Systems" and pe.signatures[i].serial=="58:a5:41:d5:0f:9e:2f:ab:43:80:c6:a2:ed:43:3b:82" and 1341792000<=pe.signatures[i].not_after)
}
