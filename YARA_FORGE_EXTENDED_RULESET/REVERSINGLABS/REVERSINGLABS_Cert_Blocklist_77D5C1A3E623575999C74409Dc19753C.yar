import "pe"

rule REVERSINGLABS_Cert_Blocklist_77D5C1A3E623575999C74409Dc19753C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8f8ce24d-8330-509a-a7a1-2727c6f8bdd9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14748-L14764"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "54921ce39a0876511b33ac6fa088c3342e2ea7fa037423fe72825bfe9c83bce6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="77:d5:c1:a3:e6:23:57:59:99:c7:44:09:dc:19:75:3c" and 1475884800<=pe.signatures[i].not_after)
}
