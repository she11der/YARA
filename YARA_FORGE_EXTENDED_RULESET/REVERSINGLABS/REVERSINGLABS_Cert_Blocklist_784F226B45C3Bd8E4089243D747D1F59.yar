import "pe"

rule REVERSINGLABS_Cert_Blocklist_784F226B45C3Bd8E4089243D747D1F59 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f2a979e0-2027-5143-8cb4-ffcfd19faf45"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2578-L2594"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "df8ca35a07ec6815d1efb68fa6fbf8f80c57032ecb99d0b038da0604ceffe8cf"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FSPro Labs" and pe.signatures[i].serial=="78:4f:22:6b:45:c3:bd:8e:40:89:24:3d:74:7d:1f:59" and 1242777599<=pe.signatures[i].not_after)
}
