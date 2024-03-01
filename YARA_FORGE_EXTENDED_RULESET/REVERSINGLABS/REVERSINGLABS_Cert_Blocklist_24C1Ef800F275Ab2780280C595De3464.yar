import "pe"

rule REVERSINGLABS_Cert_Blocklist_24C1Ef800F275Ab2780280C595De3464 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "251212a5-95ce-5d9f-aec0-e6d3dd099349"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7070-L7086"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7536ec92f388234bea3b33bee4af52e0e0ce9cd86b1c8321a503f70bfe5faa76"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HOLGAN LIMITED" and pe.signatures[i].serial=="24:c1:ef:80:0f:27:5a:b2:78:02:80:c5:95:de:34:64" and 1614729600<=pe.signatures[i].not_after)
}
