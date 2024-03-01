import "pe"

rule REVERSINGLABS_Cert_Blocklist_31062E483E0106B18C982F0053185C36 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Sakula malware."
		author = "ReversingLabs"
		id = "84bce7c1-efba-5a76-8865-dcfcc8e50d41"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2122-L2138"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e45fc5b4d1b9f5cd35c56aad381e26e30675a9d99747cd318f3c77ea2af0e14a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MICRO DIGITAL INC." and pe.signatures[i].serial=="31:06:2e:48:3e:01:06:b1:8c:98:2f:00:53:18:5c:36" and 1332287999<=pe.signatures[i].not_after)
}
