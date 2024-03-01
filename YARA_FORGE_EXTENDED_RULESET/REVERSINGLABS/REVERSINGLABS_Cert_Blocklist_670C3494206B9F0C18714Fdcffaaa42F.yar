import "pe"

rule REVERSINGLABS_Cert_Blocklist_670C3494206B9F0C18714Fdcffaaa42F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "210a0c72-7eb7-5c78-bf5b-1ac292e7fa11"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9112-L9128"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3b1e244b5f543a05beb2475020aa20dfc723f4dce3a5a0a963db1672d3295721"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ADRIATIK PORT SERVIS, d.o.o." and pe.signatures[i].serial=="67:0c:34:94:20:6b:9f:0c:18:71:4f:dc:ff:aa:a4:2f" and 1622160000<=pe.signatures[i].not_after)
}
