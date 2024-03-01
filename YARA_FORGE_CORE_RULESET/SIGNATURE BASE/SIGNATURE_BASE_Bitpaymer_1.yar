rule SIGNATURE_BASE_Bitpaymer_1
{
	meta:
		description = "Rule to detect newer Bitpaymer samples. Rule is based on BitPaymer custom packer"
		author = "Morphisec labs"
		id = "916de232-1f1b-5853-a57f-623812cfed16"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://blog.morphisec.com/bitpaymer-ransomware-with-new-custom-packer-framework"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_crime_bitpaymer.yar#L1-L12"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0c236794c04f0805d4611cfaf43369eeb4d0e65d6c697e6c5e6afd321fbca629"
		score = 75
		quality = 85
		tags = ""

	strings:
		$opcodes1 = {B9 ?? 00 00 00 FF 14 0F B8 FF 00 00 00 C3 89 45 FC}
		$opcodes2 = {61 55 FF 54 B7 01 B0 FF C9 C3 CC 89 45 FC}

	condition:
		( uint16(0)==0x5a4d) and ($opcodes1 or $opcodes2)
}
