import "pe"

rule REVERSINGLABS_Cert_Blocklist_Dbc03Ca7E6Ae6Db6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a5ac5da6-0bb0-5327-ac3a-b53d2f103fe6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11008-L11026"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0077b9c46ddd98a4929878ba4ba9476ed7fb1d7bf6e30c3ae0f950445d01e8f3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPIDER DEVELOPMENTS PTY LTD" and (pe.signatures[i].serial=="00:db:c0:3c:a7:e6:ae:6d:b6" or pe.signatures[i].serial=="db:c0:3c:a7:e6:ae:6d:b6") and 1600826873<=pe.signatures[i].not_after)
}
