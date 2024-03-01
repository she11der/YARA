import "pe"

rule REVERSINGLABS_Cert_Blocklist_3A1B397Fd9451E3B5891Fc69681Ed73D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6bdba43f-4003-5807-9adc-20691fbc8d14"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16764-L16780"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ca43c7bacd8cb5a896c3135abf4a131bdb4a7f5093e64c8d1df743fad0c1c64a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yongli Zhang" and pe.signatures[i].serial=="3a:1b:39:7f:d9:45:1e:3b:58:91:fc:69:68:1e:d7:3d" and 1470614400<=pe.signatures[i].not_after)
}
