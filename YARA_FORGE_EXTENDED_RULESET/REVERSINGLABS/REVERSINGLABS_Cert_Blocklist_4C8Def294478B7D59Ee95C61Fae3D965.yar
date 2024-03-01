import "pe"

rule REVERSINGLABS_Cert_Blocklist_4C8Def294478B7D59Ee95C61Fae3D965 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "549249df-690c-5b75-ac1a-77b509c9e163"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6920-L6936"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3b7b10afa5f0212bd494ba8fe32bef18f2bbd77c8ab2ad498b9557a0575cc177"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DREAM SECURITY USA INC" and pe.signatures[i].serial=="4c:8d:ef:29:44:78:b7:d5:9e:e9:5c:61:fa:e3:d9:65" and 1592961292<=pe.signatures[i].not_after)
}
