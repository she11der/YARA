import "pe"

rule REVERSINGLABS_Cert_Blocklist_7D824Ba1F7F730319C50D64C9A7Ed507 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4372aea7-a25b-5211-befd-9e0bcfb09199"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2302-L2318"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "407611603974c910d9a6a0ed71ecdf54ddcc59abb0f48c60846e61d6d4191933"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "joaweb" and pe.signatures[i].serial=="7d:82:4b:a1:f7:f7:30:31:9c:50:d6:4c:9a:7e:d5:07" and 1238025599<=pe.signatures[i].not_after)
}
