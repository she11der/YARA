import "pe"

rule REVERSINGLABS_Cert_Blocklist_D8530214Ca0F512946496B5164C61201 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0125a67a-d5e7-5c93-a58c-cacb6d8fa60b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4910-L4928"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "377962915586c9f5a5737c24b698c96efc2e819e52ee16109c405f9af2d57e7f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DJ ONLINE MARKETING LIMITED" and (pe.signatures[i].serial=="00:d8:53:02:14:ca:0f:51:29:46:49:6b:51:64:c6:12:01" or pe.signatures[i].serial=="d8:53:02:14:ca:0f:51:29:46:49:6b:51:64:c6:12:01") and 1595485920<=pe.signatures[i].not_after)
}
