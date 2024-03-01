import "pe"

rule REVERSINGLABS_Cert_Blocklist_11212F502836A784752160351Defb136Cf09 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7609083d-145b-5594-a04b-72c2862873eb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15296-L15312"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "63d4c1aaafdf6de14d0ae78035644cf6b0fefab8b0063d2566ca38af9f9498d2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EVANGEL TECHNOLOGY(HK) LIMITED" and pe.signatures[i].serial=="11:21:2f:50:28:36:a7:84:75:21:60:35:1d:ef:b1:36:cf:09" and 1463726573<=pe.signatures[i].not_after)
}
