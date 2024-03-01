import "pe"

rule REVERSINGLABS_Cert_Blocklist_5389Cc6286Da3Bfa1Dc4Df498Bf68361 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "973aaf33-25a2-5f40-a5a7-d9f77e3589b3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14130-L14146"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d25d998c980f47f4da065155451503dcbc677ad041af85a6ed7060ecadec66b3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Joerm.com" and pe.signatures[i].serial=="53:89:cc:62:86:da:3b:fa:1d:c4:df:49:8b:f6:83:61" and 1495497600<=pe.signatures[i].not_after)
}
