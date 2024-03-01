import "pe"

rule REVERSINGLABS_Cert_Blocklist_029Bf7E1Cb09Fe277564Bd27C267De5A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1e66d13c-3345-592c-9bf8-b8a566c8b9e6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10162-L10178"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3f64372d11d61c669580d90cdf2201e7f2904fb3d73d27be2ff1559c9c37614a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAMOYAJ LIMITED" and pe.signatures[i].serial=="02:9b:f7:e1:cb:09:fe:27:75:64:bd:27:c2:67:de:5a" and 1637712001<=pe.signatures[i].not_after)
}
