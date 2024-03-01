import "pe"

rule REVERSINGLABS_Cert_Blocklist_5B440A47E8Ce3Dd202271E5C7A666C78 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6f9852cb-277d-5942-b3f7-525593a41027"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5386-L5402"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "eb4387d58e391c356ed774d8c13bb4bbb2befed585bb44674459d3ef519aec58"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Master Networking s.r.o." and pe.signatures[i].serial=="5b:44:0a:47:e8:ce:3d:d2:02:27:1e:5c:7a:66:6c:78" and 1601895571<=pe.signatures[i].not_after)
}
