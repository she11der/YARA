import "pe"

rule REVERSINGLABS_Cert_Blocklist_6967A89Bcf6Efef160Aaeebbff376C0A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d6714f50-600b-5437-8be6-097f7dd93dc7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1870-L1886"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "deb7465e453aa5838f81e15e270abc958a65e1a6051a88a5910244edbe874451"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Chang Yucheng" and pe.signatures[i].serial=="69:67:a8:9b:cf:6e:fe:f1:60:aa:ee:bb:ff:37:6c:0a" and 1451174399<=pe.signatures[i].not_after)
}
