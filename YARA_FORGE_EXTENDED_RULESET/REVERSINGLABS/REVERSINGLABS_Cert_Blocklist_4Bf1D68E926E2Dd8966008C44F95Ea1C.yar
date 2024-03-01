import "pe"

rule REVERSINGLABS_Cert_Blocklist_4Bf1D68E926E2Dd8966008C44F95Ea1C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c82170a4-911c-5206-bae8-6503a5449df9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2880-L2896"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "44b5aae8380e3590ebb6e2365e89b3827432e8330e5290dc8f8603a00bcf62f6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Technical and Commercial Consulting Pvt. Ltd." and pe.signatures[i].serial=="4b:f1:d6:8e:92:6e:2d:d8:96:60:08:c4:4f:95:ea:1c" and 1322092799<=pe.signatures[i].not_after)
}
