import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Ee50Bb98Fadca2D662A0920E76685A2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5c35c73e-e4f6-5707-ad91-1db7c0a0ec81"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17070-L17086"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d232923ed962fbf4a9a30890778c2380d6c6967a693c6f77c2f558bb4347e60e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABDULKADIR SAHIN" and pe.signatures[i].serial=="3e:e5:0b:b9:8f:ad:ca:2d:66:2a:09:20:e7:66:85:a2" and 1330041600<=pe.signatures[i].not_after)
}
