import "pe"

rule REVERSINGLABS_Cert_Blocklist_22Accad235Fb1Ac7422Ebe5Ea7Ac9Bc5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "218543f3-298f-5038-8fa9-3abeda9e4d8f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15332-L15348"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b348c502aeae036f6d17283260ed4479427f89c8c25f2b6d59e137e90694dbe4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IMS INTERACTIVE MEDIA SOLUTIONS" and pe.signatures[i].serial=="22:ac:ca:d2:35:fb:1a:c7:42:2e:be:5e:a7:ac:9b:c5" and 1019001600<=pe.signatures[i].not_after)
}
