import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Def22Ef4C645B1Decfb36B6D3539Dbf : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "aeb10a64-633c-5fc6-87af-360e1a402ad4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16546-L16562"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "655ed87ee65f937c7cec95085fe612f8d733e0853c87aa50b4aa1fda9e5f7a5d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and pe.signatures[i].serial=="7d:ef:22:ef:4c:64:5b:1d:ec:fb:36:b6:d3:53:9d:bf" and 1474416000<=pe.signatures[i].not_after)
}
