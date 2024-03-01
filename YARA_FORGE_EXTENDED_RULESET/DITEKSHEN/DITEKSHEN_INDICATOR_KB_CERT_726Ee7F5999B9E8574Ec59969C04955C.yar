import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_726Ee7F5999B9E8574Ec59969C04955C : FILE
{
	meta:
		description = "Detects IntelliAdmin commercial remote administration signing certificate"
		author = "ditekSHen"
		id = "5e88abd2-97d5-5271-ace5-6b7cb2cd6633"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4101-L4112"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "494afa3711d93c56d52b8ae944db737cb53db8d27f2255c7045c3bf4478995a3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2fb952bc1e3fcf85f68d6e2cb5fc46a519ce3fa9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IntelliAdmin, LLC" and pe.signatures[i].serial=="72:6e:e7:f5:99:9b:9e:85:74:ec:59:96:9c:04:95:5c")
}
