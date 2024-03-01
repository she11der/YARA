import "pe"

rule REVERSINGLABS_Cert_Blocklist_E38259Cf24Cc702Ce441B683Ad578911 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fc5df86f-b8c9-58b1-bd41-e03ed50829dd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5004-L5022"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2428df14a18f4aed1a3db85c1fb43a847fae8a922c6dc948f3bc514dc4cae09c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Akhirah Technologies Inc." and (pe.signatures[i].serial=="00:e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11" or pe.signatures[i].serial=="e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11") and 1597276800<=pe.signatures[i].not_after)
}
