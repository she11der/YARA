import "pe"

rule REVERSINGLABS_Cert_Blocklist_C6Ed0Efe2844Fa44Aae350C6845C3331 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d748bea4-8d2b-53b2-8184-ea0972ad9199"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16396-L16414"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5c4afcd8ceb5cc2f1df2303183ede2081b86365eeee7d4e1319a8ed9a45bbf0b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE COMPANY OF WORDS LTD" and (pe.signatures[i].serial=="00:c6:ed:0e:fe:28:44:fa:44:aa:e3:50:c6:84:5c:33:31" or pe.signatures[i].serial=="c6:ed:0e:fe:28:44:fa:44:aa:e3:50:c6:84:5c:33:31") and 1549324800<=pe.signatures[i].not_after)
}
