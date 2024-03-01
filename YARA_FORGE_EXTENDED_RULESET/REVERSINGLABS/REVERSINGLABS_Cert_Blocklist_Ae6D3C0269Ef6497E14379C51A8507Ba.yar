import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ae6D3C0269Ef6497E14379C51A8507Ba : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5b8e7730-cb8b-5c51-9784-d944453bc898"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6712-L6730"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "23570962c80bddce28a3dee9d4d864cf3cf64018eec6fbcbdd3ca2658c9f660f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VELES PROPERTIES LIMITED" and (pe.signatures[i].serial=="00:ae:6d:3c:02:69:ef:64:97:e1:43:79:c5:1a:85:07:ba" or pe.signatures[i].serial=="ae:6d:3c:02:69:ef:64:97:e1:43:79:c5:1a:85:07:ba") and 1578566034<=pe.signatures[i].not_after)
}
