import "pe"

rule REVERSINGLABS_Cert_Blocklist_0761110Efe0B688C469D687512828C1F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e8575a71-124b-5040-91b1-ccad371e10da"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17254-L17270"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0ba60e1f58c7335ba5aa261031d09ee83a0ee51e05f8f26078b2a5c776ad0add"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ENP Games Co., Ltd." and pe.signatures[i].serial=="07:61:11:0e:fe:0b:68:8c:46:9d:68:75:12:82:8c:1f" and 1433721600<=pe.signatures[i].not_after)
}
