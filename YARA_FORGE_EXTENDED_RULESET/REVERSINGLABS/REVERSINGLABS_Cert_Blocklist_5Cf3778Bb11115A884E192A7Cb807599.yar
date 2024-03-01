import "pe"

rule REVERSINGLABS_Cert_Blocklist_5Cf3778Bb11115A884E192A7Cb807599 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cd643ad5-254a-5c53-a6f2-b263ff539cd3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6538-L6556"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4242ef4a30bb09463ec5a6df9367915788a2aa782df6c463bcf966d2aad63c1d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SLOMATIC d.o.o." and (pe.signatures[i].serial=="00:5c:f3:77:8b:b1:11:15:a8:84:e1:92:a7:cb:80:75:99" or pe.signatures[i].serial=="5c:f3:77:8b:b1:11:15:a8:84:e1:92:a7:cb:80:75:99") and 1605006199<=pe.signatures[i].not_after)
}
