import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Bc9B800F480691Bd6B60963466B0C75 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "614f88ca-183a-548b-99f1-30cf4c4027ce"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9420-L9436"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6a498fd30c611976e9aad2f9b85b13c3c29246582cdfefc800615db88e40dac2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HasCred ApS" and pe.signatures[i].serial=="0b:c9:b8:00:f4:80:69:1b:d6:b6:09:63:46:6b:0c:75" and 1629158400<=pe.signatures[i].not_after)
}
