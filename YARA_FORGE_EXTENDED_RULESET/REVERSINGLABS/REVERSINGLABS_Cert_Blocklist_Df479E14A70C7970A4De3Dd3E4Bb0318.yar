import "pe"

rule REVERSINGLABS_Cert_Blocklist_Df479E14A70C7970A4De3Dd3E4Bb0318 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "465fc41c-920d-55e6-8616-a51d1f77b158"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4704-L4722"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "35b1f04cf5d5d1d89db537bf75737e3af5945e594f4d4231e9ae3e7fba52fc0d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SOFTWARE HUB IT LTD" and (pe.signatures[i].serial=="00:df:47:9e:14:a7:0c:79:70:a4:de:3d:d3:e4:bb:03:18" or pe.signatures[i].serial=="df:47:9e:14:a7:0c:79:70:a4:de:3d:d3:e4:bb:03:18") and 1591660800<=pe.signatures[i].not_after)
}
