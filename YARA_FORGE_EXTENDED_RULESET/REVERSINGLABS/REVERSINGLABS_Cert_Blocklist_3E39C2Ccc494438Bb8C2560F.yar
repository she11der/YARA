import "pe"

rule REVERSINGLABS_Cert_Blocklist_3E39C2Ccc494438Bb8C2560F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "87477ad5-fc7e-5407-9c6e-bef3d4d8981d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16564-L16580"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3b4a55149b3895eeea5f96297d1fc9787eb74e2fcef8170148ef1a2ced334311"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="3e:39:c2:cc:c4:94:43:8b:b8:c2:56:0f" and 1466142876<=pe.signatures[i].not_after)
}
