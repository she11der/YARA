import "pe"

rule REVERSINGLABS_Cert_Blocklist_333705C20B56E57F60B5Eb191Eef0D90 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7f98e550-fca6-564f-bbad-40e153f17adc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9766-L9782"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "30eeec467b837f6b1759cd0fd6a8bc2e8942f2400df170c671287f4159652479"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TASK Holding ApS" and pe.signatures[i].serial=="33:37:05:c2:0b:56:e5:7f:60:b5:eb:19:1e:ef:0d:90" and 1634233052<=pe.signatures[i].not_after)
}
