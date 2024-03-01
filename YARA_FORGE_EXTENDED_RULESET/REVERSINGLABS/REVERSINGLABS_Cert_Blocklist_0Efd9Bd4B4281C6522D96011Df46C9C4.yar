import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Efd9Bd4B4281C6522D96011Df46C9C4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7bd6616b-fef7-56aa-a78a-606601afa4f3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9294-L9310"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8f8a5e3457c05c5e70e33041c5b0b971cf8f19313d47055fd760ed17d94c8794"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE9\\x9B\\xB7\\xE7\\xA5\\x9E\\xEF\\xBC\\x88\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xEF\\xBC\\x89\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="0e:fd:9b:d4:b4:28:1c:65:22:d9:60:11:df:46:c9:c4" and 1586249095<=pe.signatures[i].not_after)
}
