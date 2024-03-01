import "pe"

rule REVERSINGLABS_Cert_Blocklist_13794371C052Ec0559E9B492Abb25C26 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "31f119a3-e0da-5875-826f-68c40c6f8b88"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5082-L5098"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7383d1fb1fa6e49f8fa9e1eecfe3fcedb8a11702fbd3700630a11b12da29fedf"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Carmel group LLC" and pe.signatures[i].serial=="13:79:43:71:c0:52:ec:05:59:e9:b4:92:ab:b2:5c:26" and 1599177600<=pe.signatures[i].not_after)
}
