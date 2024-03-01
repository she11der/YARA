import "pe"

rule REVERSINGLABS_Cert_Blocklist_5C7E78F53C31D6Aa5B45De14B47Eb5C4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5906107a-03ce-5ca4-b0a7-12b0b45359dd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5100-L5116"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7521abc5c93f0336af4fab95268962aa3d3fb48fed6a8ba7fdb98e373158b327"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cubic Information Systems, UAB" and pe.signatures[i].serial=="5c:7e:78:f5:3c:31:d6:aa:5b:45:de:14:b4:7e:b5:c4" and 1579824000<=pe.signatures[i].not_after)
}
