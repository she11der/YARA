import "pe"

rule REVERSINGLABS_Cert_Blocklist_115Cf1353A0E33E19099A4867A4C750A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c2564461-6731-5d7b-8dbb-560929b568d0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6518-L6536"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2a3353c655531b113dc019a86288310881e3bbcb6c03670a805f22b185e09e6c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "212 NY Gifts, Inc." and (pe.signatures[i].serial=="00:11:5c:f1:35:3a:0e:33:e1:90:99:a4:86:7a:4c:75:0a" or pe.signatures[i].serial=="11:5c:f1:35:3a:0e:33:e1:90:99:a4:86:7a:4c:75:0a") and 1605515909<=pe.signatures[i].not_after)
}
