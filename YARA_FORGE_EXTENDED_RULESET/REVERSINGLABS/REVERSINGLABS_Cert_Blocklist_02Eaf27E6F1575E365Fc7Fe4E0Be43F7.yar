import "pe"

rule REVERSINGLABS_Cert_Blocklist_02Eaf27E6F1575E365Fc7Fe4E0Be43F7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5d1aad80-9444-5cc3-8ff4-b70fb089cda0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16492-L16508"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "333a43bdfbc400727b8eae1efeb03484b959fc45ed6b8b0dd5e6a553fa27e87f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Theravada Solutions Ltd" and pe.signatures[i].serial=="02:ea:f2:7e:6f:15:75:e3:65:fc:7f:e4:e0:be:43:f7" and 1562889600<=pe.signatures[i].not_after)
}
