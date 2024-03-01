import "pe"

rule REVERSINGLABS_Cert_Blocklist_43Db4448D870D7Bdc275F36A01Fba36F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "47b3e681-87ae-5e70-8d02-18aa0daab0dc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1726-L1742"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "951e35e2c3f1bd90a33f8b76b6ede5686ee9b9c97a4c71df5b9dff15956209c5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "3-T TOV" and pe.signatures[i].serial=="43:db:44:48:d8:70:d7:bd:c2:75:f3:6a:01:fb:a3:6f" and 1436227199<=pe.signatures[i].not_after)
}
