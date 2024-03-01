import "pe"

rule REVERSINGLABS_Cert_Blocklist_8Cff807Edaf368A60E4106906D8Df319 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c964a540-6124-52f0-b17f-692cd4b9b3af"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4646-L4664"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6fc98519faf218d90bb4e01821e6014e009c0b525cfd3c906a64ef82bc20beda"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KRAFT BOKS OOO" and (pe.signatures[i].serial=="00:8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19" or pe.signatures[i].serial=="8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19") and 1598334455<=pe.signatures[i].not_after)
}
