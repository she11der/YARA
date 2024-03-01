import "pe"

rule REVERSINGLABS_Cert_Blocklist_34Ec9565805F34204C6966Fb81E36Ba1 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bd032608-8622-5c7a-a3a7-808d73e611d7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16726-L16742"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e434a02f5b9b22a25d8fe7a0bb7bd81b1cd8bc5356b4b626e3bfceb3f554a085"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="34:ec:95:65:80:5f:34:20:4c:69:66:fb:81:e3:6b:a1" and 1476921600<=pe.signatures[i].not_after)
}
