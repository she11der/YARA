import "pe"

rule REVERSINGLABS_Cert_Blocklist_9813229Efe0046D23542Cc7569D5A403 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0cf7573f-290d-58ac-989f-f82e9313d54e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3676-L3694"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0d8f0df83572b8d31f29cb76f44d524fd1ae0467d2d99af959e45694524d18e8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO \"MPS\"" and (pe.signatures[i].serial=="00:98:13:22:9e:fe:00:46:d2:35:42:cc:75:69:d5:a4:03" or pe.signatures[i].serial=="98:13:22:9e:fe:00:46:d2:35:42:cc:75:69:d5:a4:03") and 1575849600<=pe.signatures[i].not_after)
}
