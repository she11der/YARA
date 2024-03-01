import "pe"

rule REVERSINGLABS_Cert_Blocklist_093Fe63D1A5F68F14Ecaac871A03F7A3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ce0b23fd-5f79-5b90-8d5c-2ff59ac39df6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4068-L4084"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "333c58a9af2d94604b637ab0a7280b6688a89ff73e30a93a8daed040fab7f620"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPECTACLE IMAGE LTD" and pe.signatures[i].serial=="09:3f:e6:3d:1a:5f:68:f1:4e:ca:ac:87:1a:03:f7:a3" and 1562716800<=pe.signatures[i].not_after)
}
