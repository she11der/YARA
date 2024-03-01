import "pe"

rule REVERSINGLABS_Cert_Blocklist_9B108B8A1Daa0D5581F59Fcee0447901 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cacb2af8-dbc6-5d61-a2d5-641c5c09bc79"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2486-L2504"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "696e3da511f74f9cfb10b96130a36ae9f48c22f1e0deb76092db1262980ab3ac"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CharacTell Ltd" and (pe.signatures[i].serial=="00:9b:10:8b:8a:1d:aa:0d:55:81:f5:9f:ce:e0:44:79:01" or pe.signatures[i].serial=="9b:10:8b:8a:1d:aa:0d:55:81:f5:9f:ce:e0:44:79:01") and 1380671999<=pe.signatures[i].not_after)
}
