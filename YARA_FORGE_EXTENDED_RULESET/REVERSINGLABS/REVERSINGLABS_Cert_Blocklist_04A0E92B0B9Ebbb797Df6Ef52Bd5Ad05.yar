import "pe"

rule REVERSINGLABS_Cert_Blocklist_04A0E92B0B9Ebbb797Df6Ef52Bd5Ad05 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c6ba359e-4883-534d-bc86-8c063e54c92f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16854-L16870"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ff2a2d06c48bd3426fa42526d966152e3e7166c4170b4e08bb65ee5d876eda93"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and pe.signatures[i].serial=="04:a0:e9:2b:0b:9e:bb:b7:97:df:6e:f5:2b:d5:ad:05" and 1479081600<=pe.signatures[i].not_after)
}
