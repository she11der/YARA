import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A01A91Cce63Ede5Eaa3Dac4883Aea05 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a1efbce8-3cca-5e07-a652-d67007c72a18"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7106-L7122"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "58a26b44e485814fa645bfa490f3442745884026bb7a70327d4f51645ad3f69c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Seacloud Technologies Pte. Ltd." and pe.signatures[i].serial=="0a:01:a9:1c:ce:63:ed:e5:ea:a3:da:c4:88:3a:ea:05" and 1618876800<=pe.signatures[i].not_after)
}
