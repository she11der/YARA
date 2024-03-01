import "pe"

rule REVERSINGLABS_Cert_Blocklist_2Ca028D1A4De0Eb743135Edecf74D7Af : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "19e1bce7-ad37-5223-b934-b20e78dfd071"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1236-L1252"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "60b6351194e23153d425eaa0c25f840080a29abb5eb1bbcd41bb76a3d4130edd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Adobe Systems" and pe.signatures[i].serial=="2c:a0:28:d1:a4:de:0e:b7:43:13:5e:de:cf:74:d7:af" and 1341792000<=pe.signatures[i].not_after)
}
