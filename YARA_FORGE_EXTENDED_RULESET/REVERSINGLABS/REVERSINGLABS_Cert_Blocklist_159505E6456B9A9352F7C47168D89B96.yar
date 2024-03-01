import "pe"

rule REVERSINGLABS_Cert_Blocklist_159505E6456B9A9352F7C47168D89B96 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3d078c5d-e469-54f1-bd69-aebeec1c25f1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16836-L16852"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d6d0d5c86dd88afa29fb3c7cc3c0ab2e3401637a23e062ee9bab693a715cf16f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shan Feng" and pe.signatures[i].serial=="15:95:05:e6:45:6b:9a:93:52:f7:c4:71:68:d8:9b:96" and 1469404800<=pe.signatures[i].not_after)
}
