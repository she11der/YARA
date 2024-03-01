import "pe"

rule REVERSINGLABS_Cert_Blocklist_557B0Abf44045827F1F36Efbc96271Ec : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "64db0b43-b73f-594d-9f04-2cdf76df7c9b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15828-L15844"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "633e8d6b44d62443d991738fa82b9742ac5634051bba5d0cdb3d6b35d66bdc8f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yuanyuan Zhang" and pe.signatures[i].serial=="55:7b:0a:bf:44:04:58:27:f1:f3:6e:fb:c9:62:71:ec" and 1480291200<=pe.signatures[i].not_after)
}
