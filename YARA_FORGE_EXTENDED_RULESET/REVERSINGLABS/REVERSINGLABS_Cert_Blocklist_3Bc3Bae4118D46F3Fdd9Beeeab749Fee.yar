import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Bc3Bae4118D46F3Fdd9Beeeab749Fee : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0d2f1f5f-119a-5069-abcb-e4e93d9964c3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1690-L1706"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fcbda27f8bf4dca8aa32103bb344380c82f0c701c25766df94c182ef94805a12"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\x9D\\x8E\\xE9\\x9B\\xAA\\xE6\\xA2\\x85" and pe.signatures[i].serial=="3b:c3:ba:e4:11:8d:46:f3:fd:d9:be:ee:ab:74:9f:ee" and 1442275199<=pe.signatures[i].not_after)
}
