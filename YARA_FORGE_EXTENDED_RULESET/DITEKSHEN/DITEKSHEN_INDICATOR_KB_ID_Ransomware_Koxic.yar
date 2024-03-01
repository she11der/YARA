rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Koxic
{
	meta:
		description = "Detects files referencing identities associated with LokiLocker ransomware"
		author = "ditekShen"
		id = "4c4ff722-cac1-5967-9e79-681f47566e96"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L571-L580"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ca4d0e85cf4c7a134609262e21d5cef98100ba0a046d17ffe51bf3975dc7cae9"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "wilhelmkox@tutanota.com" ascii wide nocase
		$s2 = "F3C777D22A0686055A3558917315676D607026B680DA5C8D3D4D887017A2A844F546AE59F59F" ascii wide

	condition:
		any of them
}
