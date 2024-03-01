import "pe"

rule REVERSINGLABS_Cert_Blocklist_7E6Bc7E5A49E2C28E6F5D042 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a7b815d9-e247-5de1-9bcb-96294b3b91c0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13076-L13092"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f378c490ff4f32fc095c822f75abac44a8d94327404cd97546c63e7441e07632"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shang Hai Jian Ji Wang Luo Ke Ji You Xian Gong Si" and pe.signatures[i].serial=="7e:6b:c7:e5:a4:9e:2c:28:e6:f5:d0:42" and 1560995284<=pe.signatures[i].not_after)
}
