import "pe"

rule REVERSINGLABS_Cert_Blocklist_065569A3E261409128A40Affa90D6D10 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "924c210b-f72a-51eb-af2a-9897faf8f677"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1162-L1178"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f8d68758704e41325e95ec69334aaf7fabe08a6d5557e0a81bac2f02d3ab5977"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Police Mutual Aid Association" and pe.signatures[i].serial=="06:55:69:a3:e2:61:40:91:28:a4:0a:ff:a9:0d:6d:10" and 1381795199<=pe.signatures[i].not_after)
}
