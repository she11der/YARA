import "pe"

rule REVERSINGLABS_Cert_Blocklist_E01407871E2146C9Baab1Ae7Ab8Ab172 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "229772ae-68a2-566b-bf61-988cb41d7d8f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12836-L12854"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1801e7f15bd5f916fc08d263a845d296d334ca9de1040008f619719c1b5c0a3b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TOV Intalev Ukraina" and (pe.signatures[i].serial=="00:e0:14:07:87:1e:21:46:c9:ba:ab:1a:e7:ab:8a:b1:72" or pe.signatures[i].serial=="e0:14:07:87:1e:21:46:c9:ba:ab:1a:e7:ab:8a:b1:72") and 1464220800<=pe.signatures[i].not_after)
}
