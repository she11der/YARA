import "pe"

rule REVERSINGLABS_Cert_Blocklist_2D88C0Af1Fe2609961C171213C03Bd23 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0e844bef-1cfe-5eba-af4d-d8477e55470c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14186-L14202"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2d181b9b517732f14d196c1a6c5661d8de4dbbfe6f120954dd3f9dcad00ff0fe"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zhuzhou Lizhong Precision Manufacturing Technology Co., Ltd." and pe.signatures[i].serial=="2d:88:c0:af:1f:e2:60:99:61:c1:71:21:3c:03:bd:23" and 1683676800<=pe.signatures[i].not_after)
}
