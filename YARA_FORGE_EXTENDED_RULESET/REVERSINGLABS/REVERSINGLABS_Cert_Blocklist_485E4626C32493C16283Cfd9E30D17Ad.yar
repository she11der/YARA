import "pe"

rule REVERSINGLABS_Cert_Blocklist_485E4626C32493C16283Cfd9E30D17Ad : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7e6834e5-ce32-5ba6-82cf-99d7b90fb4f0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15096-L15112"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "faf860786e8473493d24abf6e61cf0b906e98d786516be6d2098181368214020"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="48:5e:46:26:c3:24:93:c1:62:83:cf:d9:e3:0d:17:ad" and 1473292800<=pe.signatures[i].not_after)
}
