import "pe"

rule REVERSINGLABS_Cert_Blocklist_A3E62Be1572293Ad618F58A8Aa32857F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2f67abf3-390a-5c67-afed-e586e20692af"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4666-L4684"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f849898465bc651f19f6f1b54315c061466d8c5860ecf1a07f54c8c8292f6a95"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ISIDA, TOV" and (pe.signatures[i].serial=="00:a3:e6:2b:e1:57:22:93:ad:61:8f:58:a8:aa:32:85:7f" or pe.signatures[i].serial=="a3:e6:2b:e1:57:22:93:ad:61:8f:58:a8:aa:32:85:7f") and 1596585600<=pe.signatures[i].not_after)
}
