import "pe"

rule REVERSINGLABS_Cert_Blocklist_05054Fdea356F3Dd7Db479Fa : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c78d42bc-f8ca-579a-af49-ba9c7b63ef07"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14840-L14856"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "02ec52e060a6b8b3edfad0a1f5b1f2d6c409645d5233612d0d353ad74bcd4568"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="05:05:4f:de:a3:56:f3:dd:7d:b4:79:fa" and 1474436511<=pe.signatures[i].not_after)
}
