import "pe"

rule REVERSINGLABS_Cert_Blocklist_73E2F34C9C2435F29Bbe0A3C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "284c206f-8a0c-5bb6-8f28-d8e5e60efe3e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13404-L13420"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "503429e737e8bdad735cf88e2bb2877d1f52b2c38be101a7a129c02db608a347"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="73:e2:f3:4c:9c:24:35:f2:9b:be:0a:3c" and 1480312984<=pe.signatures[i].not_after)
}
