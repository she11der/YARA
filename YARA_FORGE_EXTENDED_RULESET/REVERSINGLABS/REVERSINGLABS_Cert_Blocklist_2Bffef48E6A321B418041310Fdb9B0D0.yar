import "pe"

rule REVERSINGLABS_Cert_Blocklist_2Bffef48E6A321B418041310Fdb9B0D0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6a29551f-8359-5394-9acd-00c3b25d7064"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16708-L16724"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "30a079b55b75b292f7af4f5ae99184cbb3cca1ce4cf20f2f5c961b533673db00"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "A&D DOMUS LIMITED" and pe.signatures[i].serial=="2b:ff:ef:48:e6:a3:21:b4:18:04:13:10:fd:b9:b0:d0" and 1554681600<=pe.signatures[i].not_after)
}
