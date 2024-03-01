import "pe"

rule REVERSINGLABS_Cert_Blocklist_767436921B2698Bd18400A24B01341B6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3e3b2b75-9416-5c4f-ad47-88f92039f532"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3158-L3174"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "759bbbc5929463ad68d5dcd28b30401b9ff680f522172ed8d5d7dd3772e07587"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REBROSE LEISURE LIMITED" and pe.signatures[i].serial=="76:74:36:92:1b:26:98:bd:18:40:0a:24:b0:13:41:b6" and 1556284480<=pe.signatures[i].not_after)
}
