import "pe"

rule REVERSINGLABS_Cert_Blocklist_13Ae38C9Ae21A8576C0D024D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "416c5eb3-bc6d-5fb0-a7fe-58cdd6c7c39d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15810-L15826"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7be892eaf9e2e31442f7ef5ffd296dd17696d6c95d20eb2758ede2c553b05f38"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="13:ae:38:c9:ae:21:a8:57:6c:0d:02:4d" and 1475062802<=pe.signatures[i].not_after)
}
