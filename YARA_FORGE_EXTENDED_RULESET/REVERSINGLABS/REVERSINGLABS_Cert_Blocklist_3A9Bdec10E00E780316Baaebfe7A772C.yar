import "pe"

rule REVERSINGLABS_Cert_Blocklist_3A9Bdec10E00E780316Baaebfe7A772C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "56f62454-84a1-5843-b2f4-fa84b37040f3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14076-L14092"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ea9bc11efd2969f6b7112338f2b084ea3551e072e46b1162bd47b08be549cdd4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PLAN ALPHA LIMITED" and pe.signatures[i].serial=="3a:9b:de:c1:0e:00:e7:80:31:6b:aa:eb:fe:7a:77:2c" and 1556582400<=pe.signatures[i].not_after)
}
