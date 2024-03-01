import "pe"

rule REVERSINGLABS_Cert_Blocklist_B0167124Ca59149E64D292Eb4B142014 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "384ce73e-3ad5-54d9-a140-cb242f9a91e6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4422-L4440"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "10d980d4a71dab4679376f5a6d6a6999e0b59af4f25587a7b8d1ef52a7808cc9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Euro May SP Z O O" and (pe.signatures[i].serial=="00:b0:16:71:24:ca:59:14:9e:64:d2:92:eb:4b:14:20:14" or pe.signatures[i].serial=="b0:16:71:24:ca:59:14:9e:64:d2:92:eb:4b:14:20:14") and 1585267200<=pe.signatures[i].not_after)
}
