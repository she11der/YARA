rule ELCEEF_Base64_SVG_Javascript
{
	meta:
		description = "Detects base64 encoded SVG objects containing Javascript"
		author = "marcin@ulikowski.pl"
		id = "99275772-1f4f-5616-9a9c-f76b613fe143"
		date = "2022-10-25"
		modified = "2022-12-12"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/rules/Base64_SVG_Javascript.yara#L1-L16"
		license_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/LICENSE"
		logic_hash = "e4cb08ccc75dc00b518c4ee1495409ae6bb99e7d493be55312b8d39aa9099cfc"
		score = 75
		quality = 75
		tags = ""
		hash1 = "fe394a59e961c3fbcc326e7d0ee5909596de55249e669bc4da0aed172c11fda8"
		hash2 = "f0c94f2705b1aea17f4a6c6d71c6ed725fe71bf66b03b0117060010859ca8a19"

	strings:
		$svg = "\"data:image/svg+xml;base64" wide ascii
		$js = "<script type=\"text/javascript\">" base64

	condition:
		all of them
}