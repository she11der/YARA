import "pe"

rule REVERSINGLABS_Cert_Blocklist_E573D9C8B403C41Bd59Ffa0A8Efd4168 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2e799dd9-d143-55a7-9d07-d5f289477b24"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12158-L12176"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "425126b90fe2ab7c1ec7bf2fd5a91e4438a81992f20f99ed87ec62e7f20043cd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\"VERONIKA 2\" OOO" and (pe.signatures[i].serial=="00:e5:73:d9:c8:b4:03:c4:1b:d5:9f:fa:0a:8e:fd:41:68" or pe.signatures[i].serial=="e5:73:d9:c8:b4:03:c4:1b:d5:9f:fa:0a:8e:fd:41:68") and 1563148800<=pe.signatures[i].not_after)
}
