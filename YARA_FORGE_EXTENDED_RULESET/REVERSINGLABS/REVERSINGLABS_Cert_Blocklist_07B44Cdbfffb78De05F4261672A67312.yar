import "pe"

rule REVERSINGLABS_Cert_Blocklist_07B44Cdbfffb78De05F4261672A67312 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "18787692-1233-5ea8-869c-feb530d06237"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L603-L619"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c88a8543782fc49d8aa68f3fc8052bd3316d10118dfb2ef2eef5006de657b6f1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Buster Paper Comercial Ltda" and pe.signatures[i].serial=="07:b4:4c:db:ff:fb:78:de:05:f4:26:16:72:a6:73:12" and 1359503999<=pe.signatures[i].not_after)
}
