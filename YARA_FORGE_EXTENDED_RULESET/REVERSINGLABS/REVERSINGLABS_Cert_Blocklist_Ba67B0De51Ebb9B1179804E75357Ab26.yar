import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ba67B0De51Ebb9B1179804E75357Ab26 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "63938a97-2cb3-52b0-9717-c8949e3fae46"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9880-L9898"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "69b9012fc4ab9636d159de49ff452f054030c1157cf70a95512b2a0748dad7c0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fjordland Bike Wear ApS" and (pe.signatures[i].serial=="00:ba:67:b0:de:51:eb:b9:b1:17:98:04:e7:53:57:ab:26" or pe.signatures[i].serial=="ba:67:b0:de:51:eb:b9:b1:17:98:04:e7:53:57:ab:26") and 1636145940<=pe.signatures[i].not_after)
}
