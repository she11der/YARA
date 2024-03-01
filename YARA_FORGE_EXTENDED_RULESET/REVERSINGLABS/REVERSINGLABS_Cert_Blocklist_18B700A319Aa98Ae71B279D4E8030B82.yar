import "pe"

rule REVERSINGLABS_Cert_Blocklist_18B700A319Aa98Ae71B279D4E8030B82 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8d1a98aa-a895-5e79-905c-760166352d4f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16908-L16924"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e201498acfd9afebc68321887a806bb5c1d74c64a7cd93530feae2a944bd30fa"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="18:b7:00:a3:19:aa:98:ae:71:b2:79:d4:e8:03:0b:82" and 1479686400<=pe.signatures[i].not_after)
}
