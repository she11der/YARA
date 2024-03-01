import "pe"

rule REVERSINGLABS_Cert_Blocklist_2Ce2Bd0Ad3Cfde9Ea73Eec7Ca30400Da : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "b7439b38-c8b7-5dcb-8d10-952862ce3465"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2230-L2246"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a879ecd957acd29e8a5bad6c97cd10453ab857949680b522735bd77eb561d2ee"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Media Lid" and pe.signatures[i].serial=="2c:e2:bd:0a:d3:cf:de:9e:a7:3e:ec:7c:a3:04:00:da" and 1493337599<=pe.signatures[i].not_after)
}
