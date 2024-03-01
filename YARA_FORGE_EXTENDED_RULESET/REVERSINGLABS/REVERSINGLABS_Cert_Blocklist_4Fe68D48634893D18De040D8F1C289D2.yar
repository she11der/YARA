import "pe"

rule REVERSINGLABS_Cert_Blocklist_4Fe68D48634893D18De040D8F1C289D2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "40aed582-2960-5b42-acde-7350a2595b4b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L495-L511"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "41feebc8800a084ac369b5c5721b1362d371bd503b67823986bad2839157a4b0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xinghua Yile Network Tech Co.,Ltd." and pe.signatures[i].serial=="4f:e6:8d:48:63:48:93:d1:8d:e0:40:d8:f1:c2:89:d2" and 1371081600<=pe.signatures[i].not_after)
}
