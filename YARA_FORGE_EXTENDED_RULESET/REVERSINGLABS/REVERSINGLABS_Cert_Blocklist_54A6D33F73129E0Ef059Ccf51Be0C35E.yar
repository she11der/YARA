import "pe"

rule REVERSINGLABS_Cert_Blocklist_54A6D33F73129E0Ef059Ccf51Be0C35E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1cf2bda8-05e6-5f0a-a28a-2f5fa02775c9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12012-L12028"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6fbed9c8537ea2baeb58044a934fc9741730b8a3ae4d059c23b033973d7ff7d3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STAFFORD MEAT COMPANY, INC." and pe.signatures[i].serial=="54:a6:d3:3f:73:12:9e:0e:f0:59:cc:f5:1b:e0:c3:5e" and 1607100127<=pe.signatures[i].not_after)
}
