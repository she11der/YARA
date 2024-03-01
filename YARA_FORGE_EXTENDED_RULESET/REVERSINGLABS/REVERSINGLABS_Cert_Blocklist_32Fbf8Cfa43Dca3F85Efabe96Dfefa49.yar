import "pe"

rule REVERSINGLABS_Cert_Blocklist_32Fbf8Cfa43Dca3F85Efabe96Dfefa49 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "22bd8590-7a95-564c-ad77-fb20569de51d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6480-L6496"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "73d80e6a0dc2316524a55a9627792b9b4488d238ef529f1767de182956b0865e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Foxstyle LLC" and pe.signatures[i].serial=="32:fb:f8:cf:a4:3d:ca:3f:85:ef:ab:e9:6d:fe:fa:49" and 1598255906<=pe.signatures[i].not_after)
}
