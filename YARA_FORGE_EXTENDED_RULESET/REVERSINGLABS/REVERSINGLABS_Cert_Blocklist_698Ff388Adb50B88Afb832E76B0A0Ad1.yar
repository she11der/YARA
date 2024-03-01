import "pe"

rule REVERSINGLABS_Cert_Blocklist_698Ff388Adb50B88Afb832E76B0A0Ad1 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8a6f4a15-08a5-5ca5-a743-55075726e744"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16120-L16136"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b29bc69c8fd9543dba8f7d2a18d52b1bcbb8a8ae6f553d8b232ca74709b9addc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BELLAP LIMITED" and pe.signatures[i].serial=="69:8f:f3:88:ad:b5:0b:88:af:b8:32:e7:6b:0a:0a:d1" and 1675070541<=pe.signatures[i].not_after)
}
