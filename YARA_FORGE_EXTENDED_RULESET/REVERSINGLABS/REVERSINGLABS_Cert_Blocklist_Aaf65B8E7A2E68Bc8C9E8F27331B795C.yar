import "pe"

rule REVERSINGLABS_Cert_Blocklist_Aaf65B8E7A2E68Bc8C9E8F27331B795C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ccb36b8b-301d-5cc2-9c8e-4956b92c1116"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16376-L16394"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "390d074da09d8e5b4bb2a6f4157a5125474ab5c22de62729d4fc4075edade289"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALISA L LIMITED" and (pe.signatures[i].serial=="00:aa:f6:5b:8e:7a:2e:68:bc:8c:9e:8f:27:33:1b:79:5c" or pe.signatures[i].serial=="aa:f6:5b:8e:7a:2e:68:bc:8c:9e:8f:27:33:1b:79:5c") and 1549324800<=pe.signatures[i].not_after)
}
