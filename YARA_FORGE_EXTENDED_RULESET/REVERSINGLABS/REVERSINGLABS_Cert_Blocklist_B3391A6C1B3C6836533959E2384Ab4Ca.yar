import "pe"

rule REVERSINGLABS_Cert_Blocklist_B3391A6C1B3C6836533959E2384Ab4Ca : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ab274ae3-0884-517a-a221-2c952fc9d74c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10624-L10642"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "38e38acfbfbf63b7179d2f8656f70224afa9269a7bdecd10ccbbbd92a6a216d3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VERIFIED SOFTWARE LLC" and (pe.signatures[i].serial=="00:b3:39:1a:6c:1b:3c:68:36:53:39:59:e2:38:4a:b4:ca" or pe.signatures[i].serial=="b3:39:1a:6c:1b:3c:68:36:53:39:59:e2:38:4a:b4:ca") and 1595462400<=pe.signatures[i].not_after)
}
