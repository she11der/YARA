import "pe"

rule REVERSINGLABS_Cert_Blocklist_E3B80C0932B52A708477939B0D32186F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e7cdf040-3fe2-55ed-8f66-702fb4455653"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11402-L11420"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "acdfce4dc25cbc9e9817453d5cf56c7d319bebdf7a039ea47412ec3b2f68cb02"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BISOYETUTU LTD LIMITED" and (pe.signatures[i].serial=="00:e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f" or pe.signatures[i].serial=="e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f") and 1617062400<=pe.signatures[i].not_after)
}
