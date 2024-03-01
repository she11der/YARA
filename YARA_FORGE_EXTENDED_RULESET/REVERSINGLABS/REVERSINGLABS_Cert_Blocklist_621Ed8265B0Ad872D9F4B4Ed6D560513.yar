import "pe"

rule REVERSINGLABS_Cert_Blocklist_621Ed8265B0Ad872D9F4B4Ed6D560513 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b64e640c-264f-597c-90a5-d0ad57aa5075"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1654-L1670"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c133d6eea5d27e597d0a656c7c930a5ca84adb46aa2fec66381b6b5c759e22aa"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fan Li" and pe.signatures[i].serial=="62:1e:d8:26:5b:0a:d8:72:d9:f4:b4:ed:6d:56:05:13" and 1413183357<=pe.signatures[i].not_after)
}
