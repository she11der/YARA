import "pe"

rule REVERSINGLABS_Cert_Blocklist_121Fca3Cfa4Bd011669F5Cc4E053Aa3F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ebc47e1e-e6fe-581c-86b3-22e2e67a0b81"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8054-L8070"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1edd5be3f970202be15080cd7ef19c0cce7fcba73cb6120d7cb7d518e877cf85"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kymijoen Projektipalvelut Oy" and pe.signatures[i].serial=="12:1f:ca:3c:fa:4b:d0:11:66:9f:5c:c4:e0:53:aa:3f" and 1606953600<=pe.signatures[i].not_after)
}
