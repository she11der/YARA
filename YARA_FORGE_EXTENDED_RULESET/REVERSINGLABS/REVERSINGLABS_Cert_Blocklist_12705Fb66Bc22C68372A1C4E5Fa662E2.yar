import "pe"

rule REVERSINGLABS_Cert_Blocklist_12705Fb66Bc22C68372A1C4E5Fa662E2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "78f9fdf0-d8c6-5316-8053-42f77adf95d1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10126-L10142"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f10316a26e2d34400b7c2e403eab18ab6c1cc94b35f0ac8a3f490d101d29dc8d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APRIL BROTHERS LTD" and pe.signatures[i].serial=="12:70:5f:b6:6b:c2:2c:68:37:2a:1c:4e:5f:a6:62:e2" and 1642464000<=pe.signatures[i].not_after)
}
