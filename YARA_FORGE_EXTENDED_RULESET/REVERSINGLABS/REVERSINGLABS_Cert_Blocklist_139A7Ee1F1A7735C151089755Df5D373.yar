import "pe"

rule REVERSINGLABS_Cert_Blocklist_139A7Ee1F1A7735C151089755Df5D373 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "eaab67a1-ed7a-58f3-afb3-3637c3b72020"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13204-L13220"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "86072fef7d1488dc257c3ca8fbb99620ec06f8ecb671b4e20d09d0ce6cc8601d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yongli Li" and pe.signatures[i].serial=="13:9a:7e:e1:f1:a7:73:5c:15:10:89:75:5d:f5:d3:73" and 1476057600<=pe.signatures[i].not_after)
}
