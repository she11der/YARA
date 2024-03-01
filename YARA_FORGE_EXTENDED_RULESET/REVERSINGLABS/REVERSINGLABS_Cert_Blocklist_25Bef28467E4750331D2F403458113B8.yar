import "pe"

rule REVERSINGLABS_Cert_Blocklist_25Bef28467E4750331D2F403458113B8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a97723cb-7814-5f08-af94-6244c1cf4145"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13566-L13582"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "dc59fdecf60f3781e92cfe8469be2e0c1cb1cfdd3e9f9757d159667437cb37f5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and pe.signatures[i].serial=="25:be:f2:84:67:e4:75:03:31:d2:f4:03:45:81:13:b8" and 1474156800<=pe.signatures[i].not_after)
}
