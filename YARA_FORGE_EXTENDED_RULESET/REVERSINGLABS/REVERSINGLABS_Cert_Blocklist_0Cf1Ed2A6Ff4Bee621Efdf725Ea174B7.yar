import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Cf1Ed2A6Ff4Bee621Efdf725Ea174B7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7f7ecbcd-7a92-526d-99a8-d849fffa19cb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6180-L6196"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7030c122905105c72833cfcb41692bd9a67cf456e3309afce0b8f9e65c6aa5c1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LEVEL LIST SP Z O O" and pe.signatures[i].serial=="0c:f1:ed:2a:6f:f4:be:e6:21:ef:df:72:5e:a1:74:b7" and 1603036100<=pe.signatures[i].not_after)
}
