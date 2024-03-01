import "pe"

rule REVERSINGLABS_Cert_Blocklist_0332D5C942869Bdcabf5A8266197Cd14 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b1c650bb-b53f-5cca-8cc2-4d3498285d31"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10444-L10460"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "726ac44dd8109fcd0a9120f6c0673b8ecf7d5b3a4bb81976f48402e21502201a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JAWRO SP Z O O" and pe.signatures[i].serial=="03:32:d5:c9:42:86:9b:dc:ab:f5:a8:26:61:97:cd:14" and 1622160000<=pe.signatures[i].not_after)
}
