import "pe"

rule REVERSINGLABS_Cert_Blocklist_2114Ca3Bd2Afd63D7Fa29D744992B043 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7d112cb8-a29f-5560-9c3c-cd8891623d96"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9240-L9256"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "241fe5a9f233fa36a665d22b38fd360bee21bc9832c15ac9c9d9b17adc3bb306"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MATCH CONSULTANTS LTD" and pe.signatures[i].serial=="21:14:ca:3b:d2:af:d6:3d:7f:a2:9d:74:49:92:b0:43" and 1625097600<=pe.signatures[i].not_after)
}
