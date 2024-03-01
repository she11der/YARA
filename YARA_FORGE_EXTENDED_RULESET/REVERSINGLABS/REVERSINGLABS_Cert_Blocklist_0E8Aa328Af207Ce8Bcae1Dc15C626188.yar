import "pe"

rule REVERSINGLABS_Cert_Blocklist_0E8Aa328Af207Ce8Bcae1Dc15C626188 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9718f290-6ecd-5d67-9013-af99f98fffef"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9130-L9146"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4022abb8efbda944e35ff529c5b3b3c9f6370127a945f3eec1310149bb5d06e4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PRO SAT SRL" and pe.signatures[i].serial=="0e:8a:a3:28:af:20:7c:e8:bc:ae:1d:c1:5c:62:61:88" and 1627344000<=pe.signatures[i].not_after)
}
