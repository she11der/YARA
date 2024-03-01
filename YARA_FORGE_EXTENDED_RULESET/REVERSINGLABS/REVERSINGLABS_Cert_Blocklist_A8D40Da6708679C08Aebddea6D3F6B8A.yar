import "pe"

rule REVERSINGLABS_Cert_Blocklist_A8D40Da6708679C08Aebddea6D3F6B8A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a4224bf1-1875-5b2c-b79d-998d3766d163"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15646-L15664"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "27ec32791eaeccb8aa95d023c4fc8943f0435c32d8a17bde98d7d0b02ba17e59"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VELES LTD." and (pe.signatures[i].serial=="00:a8:d4:0d:a6:70:86:79:c0:8a:eb:dd:ea:6d:3f:6b:8a" or pe.signatures[i].serial=="a8:d4:0d:a6:70:86:79:c0:8a:eb:dd:ea:6d:3f:6b:8a") and 1547424000<=pe.signatures[i].not_after)
}
