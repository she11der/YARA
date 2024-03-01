import "pe"

rule REVERSINGLABS_Cert_Blocklist_70Ae0E517D2Ef6D5Eed06B56730A1A9A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "98c19385-555e-5827-b03c-59645ad2a101"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17218-L17234"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "017eed878daf706eb96b638a8d1f4428466bc1d00ce27f32628bd249a658a813"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="70:ae:0e:51:7d:2e:f6:d5:ee:d0:6b:56:73:0a:1a:9a" and 1475193600<=pe.signatures[i].not_after)
}
