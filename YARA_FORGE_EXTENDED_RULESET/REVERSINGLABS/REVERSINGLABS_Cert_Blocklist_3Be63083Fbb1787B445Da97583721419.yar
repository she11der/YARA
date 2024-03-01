import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Be63083Fbb1787B445Da97583721419 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6839595d-b645-5963-bd96-a668bfdd667f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12912-L12928"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f39f5a632544bc01c3b4c9e2f2dd33f7109c44375f54011a34181e10da79debc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\"SMART GREY\" LLC" and pe.signatures[i].serial=="3b:e6:30:83:fb:b1:78:7b:44:5d:a9:75:83:72:14:19" and 1493942400<=pe.signatures[i].not_after)
}
