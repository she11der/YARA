import "pe"

rule REVERSINGLABS_Cert_Blocklist_06Bcb74291D96096577Bdb1E165Dce85 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "da483b60-d400-54ef-84e0-ea00b299b466"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10070-L10086"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "00b7ff8f3cbc04c48c71433c384d7a7884b856f261850e33ea4413a12cf5a1b5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Revo Security SRL" and pe.signatures[i].serial=="06:bc:b7:42:91:d9:60:96:57:7b:db:1e:16:5d:ce:85" and 1637971201<=pe.signatures[i].not_after)
}
