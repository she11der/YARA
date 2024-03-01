import "pe"

rule REVERSINGLABS_Cert_Blocklist_9245D1511923F541844Faa3C6Bfebcbe : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7d4033b8-da1d-55f5-aa80-f96636650633"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7844-L7862"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b965e897b42c39841e663cc144cf6e4a81fc9bcb64ce3a15a7ca021e95866b08"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LEHTEH d.o.o., Ljubljana" and (pe.signatures[i].serial=="00:92:45:d1:51:19:23:f5:41:84:4f:aa:3c:6b:fe:bc:be" or pe.signatures[i].serial=="92:45:d1:51:19:23:f5:41:84:4f:aa:3c:6b:fe:bc:be") and 1607040000<=pe.signatures[i].not_after)
}
