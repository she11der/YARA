import "pe"

rule REVERSINGLABS_Cert_Blocklist_Dadf44E4046372313Ee97B8E394C4079 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bebfbbd7-8d42-50a3-8efa-85b641eb069a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5118-L5136"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "170533935b91776ec2413106c55ed4a01c33f32a469a855824cac796f2e132a0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Digital Capital Management Ireland Limited" and (pe.signatures[i].serial=="00:da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79" or pe.signatures[i].serial=="da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79") and 1600244736<=pe.signatures[i].not_after)
}
