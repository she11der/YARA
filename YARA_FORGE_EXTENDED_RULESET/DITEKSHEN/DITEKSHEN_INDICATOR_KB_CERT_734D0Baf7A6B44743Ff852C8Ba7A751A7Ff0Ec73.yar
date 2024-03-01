import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_734D0Baf7A6B44743Ff852C8Ba7A751A7Ff0Ec73 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1dc06f6e-2152-516a-b9cc-0d95c098c88f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6031-L6042"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "54620c58bae2c2f9859916a58b0fef4310dd27fdada663c28bb7d58bdaefc7c5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "734d0baf7a6b44743ff852c8ba7a751a7ff0ec73"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Transition software (C) 2018" and pe.signatures[i].serial=="01")
}
