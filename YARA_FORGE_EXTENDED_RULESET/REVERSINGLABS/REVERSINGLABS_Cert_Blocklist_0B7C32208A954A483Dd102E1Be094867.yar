import "pe"

rule REVERSINGLABS_Cert_Blocklist_0B7C32208A954A483Dd102E1Be094867 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d16e74d8-2c46-508b-b518-a542603ca726"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4014-L4030"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "49e2208a7d2b5684283c1dfc9856f864d16b50f951f58e0252c97419819a46ec"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Win Sp Z O O" and pe.signatures[i].serial=="0b:7c:32:20:8a:95:4a:48:3d:d1:02:e1:be:09:48:67" and 1583884800<=pe.signatures[i].not_after)
}
