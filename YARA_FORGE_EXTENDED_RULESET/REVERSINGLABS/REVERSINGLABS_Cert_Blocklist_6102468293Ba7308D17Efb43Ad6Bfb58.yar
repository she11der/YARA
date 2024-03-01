import "pe"

rule REVERSINGLABS_Cert_Blocklist_6102468293Ba7308D17Efb43Ad6Bfb58 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bcf0f1cc-44f2-5498-b9d7-9ad3f38e33bc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14332-L14348"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c1ae1562595ac6515a071a16195b46db6fad4ee0fe9757d366ee78b914e1de7f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and pe.signatures[i].serial=="61:02:46:82:93:ba:73:08:d1:7e:fb:43:ad:6b:fb:58" and 1470960000<=pe.signatures[i].not_after)
}
