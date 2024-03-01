import "pe"

rule REVERSINGLABS_Cert_Blocklist_D8F515715Aeffef0A0E4E37F16C254Fa : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "50ffd0a0-d861-53d7-a7dc-f74ccc49eff8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9474-L9492"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3c7d57a655f76a6e5ef6b0e770db7c91d0830b6b0b37caef5ef9e3e78ad1fd75"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HOLDING LA LTD" and (pe.signatures[i].serial=="00:d8:f5:15:71:5a:ef:fe:f0:a0:e4:e3:7f:16:c2:54:fa" or pe.signatures[i].serial=="d8:f5:15:71:5a:ef:fe:f0:a0:e4:e3:7f:16:c2:54:fa") and 1619136000<=pe.signatures[i].not_after)
}
