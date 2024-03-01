import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Ae3C4Eccecda2127D43Be390A850Dda : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a9d8906b-64f6-5c5d-80e0-ab916e83b613"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8806-L8822"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8a2ff4f7a5ac996127778b1670e79291bddcb5dee6e7da2b540fd254537ee27e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PARTYNET LIMITED" and pe.signatures[i].serial=="1a:e3:c4:ec:ce:cd:a2:12:7d:43:be:39:0a:85:0d:da" and 1614902400<=pe.signatures[i].not_after)
}
