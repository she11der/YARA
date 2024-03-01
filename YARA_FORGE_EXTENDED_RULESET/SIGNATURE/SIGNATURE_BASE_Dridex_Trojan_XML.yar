rule SIGNATURE_BASE_Dridex_Trojan_XML
{
	meta:
		description = "Dridex Malware in XML Document"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		id = "a8f3406c-f8b0-559f-be12-6b2a7d401ac2"
		date = "2015-03-08"
		modified = "2023-12-05"
		reference = "https://threatpost.com/dridex-banking-trojan-spreading-via-macros-in-xml-files/111503"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_dridex_xml.yar#L1-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "25b6340d782ee20723b2f17f3434a0b27b1561ab22d5a8f859e97e0ac126f651"
		score = 75
		quality = 85
		tags = ""
		hash1 = "88d98e18ed996986d26ce4149ae9b2faee0bc082"
		hash2 = "3b2d59adadf5ff10829bb5c27961b22611676395"
		hash3 = "e528671b1b32b3fa2134a088bfab1ba46b468514"
		hash4 = "981369cd53c022b434ee6d380aa9884459b63350"
		hash5 = "96e1e7383457293a9b8f2c75270b58da0e630bea"

	strings:
		$c_xml = "<?xml version="
		$c_word = "<?mso-application progid=\"Word.Document\"?>"
		$c_macro = "w:macrosPresent=\"yes\""
		$c_binary = "<w:binData w:name="
		$c_0_chars = "<o:Characters>0</o:Characters>"
		$c_1_line = "<o:Lines>1</o:Lines>"

	condition:
		all of ($c*)
}
