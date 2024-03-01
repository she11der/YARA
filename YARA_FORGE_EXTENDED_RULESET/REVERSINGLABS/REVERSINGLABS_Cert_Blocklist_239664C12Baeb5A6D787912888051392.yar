import "pe"

rule REVERSINGLABS_Cert_Blocklist_239664C12Baeb5A6D787912888051392 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4d24a880-6fa5-5c22-875e-29f4985e3750"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12048-L12064"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ab2c228088a4c11b3a0f1a5f0acf181cc31e548781cb3f1205475bfbe39c7236"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORTH PROPERTY LTD" and pe.signatures[i].serial=="23:96:64:c1:2b:ae:b5:a6:d7:87:91:28:88:05:13:92" and 1618272000<=pe.signatures[i].not_after)
}
