import "pe"

rule REVERSINGLABS_Cert_Blocklist_B82C6553B2186C219797621Aaa233Edb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e1dd9783-078f-582e-8493-7c493cda9c62"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5404-L5422"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "72e3e1740a4adc4315d2dd9c9f7b8cee2d89c3006014dec663b70d3419f43ca3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MC Commerce SP Z o o" and (pe.signatures[i].serial=="00:b8:2c:65:53:b2:18:6c:21:97:97:62:1a:aa:23:3e:db" or pe.signatures[i].serial=="b8:2c:65:53:b2:18:6c:21:97:97:62:1a:aa:23:3e:db") and 1585785600<=pe.signatures[i].not_after)
}
