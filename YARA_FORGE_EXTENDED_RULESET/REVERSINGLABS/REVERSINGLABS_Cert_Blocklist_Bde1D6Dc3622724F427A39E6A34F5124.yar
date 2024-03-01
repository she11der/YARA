import "pe"

rule REVERSINGLABS_Cert_Blocklist_Bde1D6Dc3622724F427A39E6A34F5124 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6b6958c0-3b43-5c17-9354-d0e2326b97fd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12350-L12368"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f1cf0b6855269a771447a0b38f4a02996b6527d7df4b143b69598ed591719ca0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and (pe.signatures[i].serial=="00:bd:e1:d6:dc:36:22:72:4f:42:7a:39:e6:a3:4f:51:24" or pe.signatures[i].serial=="bd:e1:d6:dc:36:22:72:4f:42:7a:39:e6:a3:4f:51:24") and 1628553600<=pe.signatures[i].not_after)
}
