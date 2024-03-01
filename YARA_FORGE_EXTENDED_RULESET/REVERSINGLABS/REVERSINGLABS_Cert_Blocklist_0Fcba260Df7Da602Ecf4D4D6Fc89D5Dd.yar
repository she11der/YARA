import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Fcba260Df7Da602Ecf4D4D6Fc89D5Dd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ce248602-1f28-5707-b921-640271176e7f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4574-L4590"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4e9a3e516342820248ebf9b3605b8ce2dbf1d9b4255a5b74f7369dd2f1cdd9d8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Gold Stroy SP Z O O" and pe.signatures[i].serial=="0f:cb:a2:60:df:7d:a6:02:ec:f4:d4:d6:fc:89:d5:dd" and 1593388801<=pe.signatures[i].not_after)
}
