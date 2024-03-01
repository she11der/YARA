import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Dabae616705F5A51152Eac48423F354 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8b050402-d5d3-5733-9a72-02386d850a04"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14914-L14930"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0bb14ececa3a78e1a2e71cfdee8bc57678251b15151d156ef5fa754b2438ee35"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="1d:ab:ae:61:67:05:f5:a5:11:52:ea:c4:84:23:f3:54" and 1470960000<=pe.signatures[i].not_after)
}
