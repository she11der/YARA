import "pe"

rule REVERSINGLABS_Cert_Blocklist_3E795531B3265510F935187Eca59920A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "953434f4-cc19-5a0a-923b-4deaadacef00"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3176-L3192"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d597e88314f9f20283b40058dd74167d0d72f7518277a57f26c15e44b670b386"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "sasha catering ltd" and pe.signatures[i].serial=="3e:79:55:31:b3:26:55:10:f9:35:18:7e:ca:59:92:0a" and 1557243644<=pe.signatures[i].not_after)
}
