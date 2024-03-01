import "pe"

rule REVERSINGLABS_Cert_Blocklist_197Dc32D915458953562D2Fe78Bf2468 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9c25410f-6a3d-5e6e-b270-ccec3be34e80"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14804-L14820"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e61284a74765592fe97b90ca1c260efa46ea31286e6d09ab32d6c664b8271f2a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Y.L. Knafo, Ltd." and pe.signatures[i].serial=="19:7d:c3:2d:91:54:58:95:35:62:d2:fe:78:bf:24:68" and 1575331200<=pe.signatures[i].not_after)
}
