import "pe"

rule REVERSINGLABS_Cert_Blocklist_0323Cc4E38735B0E6Efba76Ea25C73B7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0f3889d5-fb57-5745-999e-7dff0ddf7ee9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14260-L14276"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "48bda7f61c9705ae70add3940f10d65fc7f7a776cec91a244f0e5bde07303831"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xingning Dexin Network Technology Co., Ltd." and pe.signatures[i].serial=="03:23:cc:4e:38:73:5b:0e:6e:fb:a7:6e:a2:5c:73:b7" and 1512000000<=pe.signatures[i].not_after)
}
