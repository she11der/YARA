import "pe"

rule REVERSINGLABS_Cert_Blocklist_6922Bb5De88E4127E1Ac6969E6A199F5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "86e16068-8b0b-5f0f-af5e-5ee9f518a915"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3252-L3268"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "39dbaa232ea9125934b3682d780e3821d12e771f2b844d027d99a432fe249d9f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SMACHNA PLITKA, TOV" and pe.signatures[i].serial=="69:22:bb:5d:e8:8e:41:27:e1:ac:69:69:e6:a1:99:f5" and 1552692162<=pe.signatures[i].not_after)
}
