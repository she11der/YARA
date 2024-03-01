import "pe"

rule REVERSINGLABS_Cert_Blocklist_C33187Fe848A65E8484Ea492Cb2Cbb18 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fa05113a-a21e-5f21-aae3-b646e5b42dfb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12762-L12780"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b66d67b74d73a143cb5301b232abd5f0f84f058223d4494b924a25dffb49037a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SELCUK GUNDOGDU" and (pe.signatures[i].serial=="00:c3:31:87:fe:84:8a:65:e8:48:4e:a4:92:cb:2c:bb:18" or pe.signatures[i].serial=="c3:31:87:fe:84:8a:65:e8:48:4e:a4:92:cb:2c:bb:18") and 1426204800<=pe.signatures[i].not_after)
}
