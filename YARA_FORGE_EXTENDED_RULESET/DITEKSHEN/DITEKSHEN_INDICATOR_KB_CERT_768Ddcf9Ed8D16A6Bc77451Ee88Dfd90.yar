import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_768Ddcf9Ed8D16A6Bc77451Ee88Dfd90 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "f7d24c5f-e102-568e-bf44-47ccaad6225c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L627-L638"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ba98f0da84b678262ee98e5c5fec2aaeab9a0c304fd4552dd27e87aa54f79cdf"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = ""
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THEESOLUTIONS LTD" and pe.signatures[i].serial=="76:8d:dc:f9:ed:8d:16:a6:bc:77:45:1e:e8:8d:fd:90")
}
