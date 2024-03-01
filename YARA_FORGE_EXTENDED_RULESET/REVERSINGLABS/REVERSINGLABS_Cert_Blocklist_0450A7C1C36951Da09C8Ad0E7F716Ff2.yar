import "pe"

rule REVERSINGLABS_Cert_Blocklist_0450A7C1C36951Da09C8Ad0E7F716Ff2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b4a56bbe-f2ba-52df-832d-35b92ab73683"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L549-L565"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cb594607ceef1b8d79145ad3905fb2c38d2ed3f3e6c8a0a793fc2dc9d0a21855"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PS Partnership" and pe.signatures[i].serial=="04:50:a7:c1:c3:69:51:da:09:c8:ad:0e:7f:71:6f:f2" and 1362182399<=pe.signatures[i].not_after)
}
