import "pe"

rule REVERSINGLABS_Cert_Blocklist_13C8351Aece71C731158980F575F4133 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b6a1eb97-f0da-571e-951c-57f49cf62057"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L99-L115"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f96723845adc8030b72c119311103d5c2cf136e79de226d31141d8b925ce8e75"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Opera Software ASA" and pe.signatures[i].serial=="13:c8:35:1a:ec:e7:1c:73:11:58:98:0f:57:5f:41:33" and 1371513600<=pe.signatures[i].not_after)
}
