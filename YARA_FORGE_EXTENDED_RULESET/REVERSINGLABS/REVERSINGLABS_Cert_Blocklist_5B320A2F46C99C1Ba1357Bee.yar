import "pe"

rule REVERSINGLABS_Cert_Blocklist_5B320A2F46C99C1Ba1357Bee : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3912fdfc-7a84-51ce-abd2-977ad183af26"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5580-L5596"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "12797f80bce9d64c6c07e185aa309a0c4f910835745a7f2cc1874fb1211624d8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REGION TOURISM LLC" and pe.signatures[i].serial=="5b:32:0a:2f:46:c9:9c:1b:a1:35:7b:ee" and 1602513116<=pe.signatures[i].not_after)
}
