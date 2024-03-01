import "pe"

rule REVERSINGLABS_Cert_Blocklist_4280F2C8Ce1D98E5F8Da7Ecb005Eeae5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "559dc522-bc23-5716-b8ad-9e9df102936b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16636-L16652"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4cc8f00a9704f595f3e48375942a19cd6f8d6c0e53afc932a61f5a4326be4bcb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and pe.signatures[i].serial=="42:80:f2:c8:ce:1d:98:e5:f8:da:7e:cb:00:5e:ea:e5" and 1476316800<=pe.signatures[i].not_after)
}
