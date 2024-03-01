import "pe"

rule REVERSINGLABS_Cert_Blocklist_66C758A22Bfbbce327616815616Ddd07 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4a7130ad-8b66-52a1-afd2-6d10776b4451"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15040-L15056"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "37f0f64e2d84ef6591e1f07a05abca35b37827d26c828269fb5f38d8546a60a7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TIM Konstrakshn, TOV" and pe.signatures[i].serial=="66:c7:58:a2:2b:fb:bc:e3:27:61:68:15:61:6d:dd:07" and 1469404800<=pe.signatures[i].not_after)
}
