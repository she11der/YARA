import "pe"

rule REVERSINGLABS_Cert_Blocklist_Cbd37C0A651913Ee25A6860D7D5Ccdf2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e56205d6-9f02-5a8a-8dd3-b8c323fba4bf"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13130-L13148"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "77cc439aea6eaa5a835b6b1aa50904c1df0d5379228e424ab2d68a3cb654834c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Amma" and (pe.signatures[i].serial=="00:cb:d3:7c:0a:65:19:13:ee:25:a6:86:0d:7d:5c:cd:f2" or pe.signatures[i].serial=="cb:d3:7c:0a:65:19:13:ee:25:a6:86:0d:7d:5c:cd:f2") and 1431734400<=pe.signatures[i].not_after)
}
