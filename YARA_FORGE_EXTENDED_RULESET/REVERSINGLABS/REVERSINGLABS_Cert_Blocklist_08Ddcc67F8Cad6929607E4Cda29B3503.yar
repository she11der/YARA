import "pe"

rule REVERSINGLABS_Cert_Blocklist_08Ddcc67F8Cad6929607E4Cda29B3503 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3563547f-556b-56e3-ad25-cfec0294fe93"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4234-L4250"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4cd975312ca825b51f34f5c89184a56526877436224c1e7407d715b28ebfd9d5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FAN-CHAI, TOV" and pe.signatures[i].serial=="08:dd:cc:67:f8:ca:d6:92:96:07:e4:cd:a2:9b:35:03" and 1564310268<=pe.signatures[i].not_after)
}
