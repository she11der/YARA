import "pe"

rule REVERSINGLABS_Cert_Blocklist_066276Af2F2C7E246D3B1Cab1B4Aa42E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "97f791d5-7a73-5da7-984e-32bb94d0e83f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8512-L8528"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "30d4fa2cbc75d3a6258cdf0374159f25ea152c39784f8b7e9c461978df865dc0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IQ Trade ApS" and pe.signatures[i].serial=="06:62:76:af:2f:2c:7e:24:6d:3b:1c:ab:1b:4a:a4:2e" and 1616630400<=pe.signatures[i].not_after)
}
