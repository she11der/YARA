import "pe"

rule REVERSINGLABS_Cert_Blocklist_4679C5398A279318365Fd77A84445699 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8d1810e7-9b64-52b3-91c6-f03832d61d3a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10462-L10478"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bdb68be92b3ba6b5eaa6e8e963529c0b9213942ba2552c687496ad5d12d5b472"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HURT GROUP HOLDINGS LIMITED" and pe.signatures[i].serial=="46:79:c5:39:8a:27:93:18:36:5f:d7:7a:84:44:56:99" and 1643846400<=pe.signatures[i].not_after)
}
