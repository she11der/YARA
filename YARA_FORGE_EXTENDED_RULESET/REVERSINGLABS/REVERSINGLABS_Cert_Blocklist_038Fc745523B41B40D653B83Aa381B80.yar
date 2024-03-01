import "pe"

rule REVERSINGLABS_Cert_Blocklist_038Fc745523B41B40D653B83Aa381B80 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3f7f9d58-3a7a-5f84-bf6e-795a9c8bcd38"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7634-L7650"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "016ca6dcb5c7c56c80e4486b84d97fb3869a959ef3e8392e4376a0a0de06092f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Optima" and pe.signatures[i].serial=="03:8f:c7:45:52:3b:41:b4:0d:65:3b:83:aa:38:1b:80" and 1606143708<=pe.signatures[i].not_after)
}
