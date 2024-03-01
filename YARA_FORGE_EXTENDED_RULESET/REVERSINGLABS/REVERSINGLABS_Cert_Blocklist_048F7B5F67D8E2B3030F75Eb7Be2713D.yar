import "pe"

rule REVERSINGLABS_Cert_Blocklist_048F7B5F67D8E2B3030F75Eb7Be2713D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e746516a-c51f-5cb8-8157-a5fe1f2c7abe"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4798-L4814"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6d1b47f3c9d7b90a5470f83a848adeebff2cf9341a1eb41ca8b45d08b469b17f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RITEIL SERVIS, OOO" and pe.signatures[i].serial=="04:8f:7b:5f:67:d8:e2:b3:03:0f:75:eb:7b:e2:71:3d" and 1591142400<=pe.signatures[i].not_after)
}
