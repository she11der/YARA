import "pe"

rule REVERSINGLABS_Cert_Blocklist_D338F8A490E37E6C2Be80A0E349929Fa : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "93ca450e-7278-5c6c-aba8-e90728570e0c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8072-L8090"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "39d9695803e96508b5ad12a7d9f8b65d13288dbe94b21a4952e096dd576e11ce"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAGUARO ApS" and (pe.signatures[i].serial=="00:d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa" or pe.signatures[i].serial=="d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa") and 1607558400<=pe.signatures[i].not_after)
}
