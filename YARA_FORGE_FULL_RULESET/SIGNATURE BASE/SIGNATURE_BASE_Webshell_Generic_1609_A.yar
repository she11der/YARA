rule SIGNATURE_BASE_Webshell_Generic_1609_A : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "4b7db4db-8699-5b4d-ab90-ce79f1160984"
		date = "2016-09-10"
		modified = "2023-12-05"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L9643-L9658"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e5a4bba3a7b1c712203fcc8b85e4089b0ff18a26e96f5a04529616dbfb9de651"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "c817a490cfd4d6377c15c9ac9bcfa136f4a45ff5b40c74f15216c030f657d035"
		hash3 = "69b9d55ea2eb4a0d9cfe3b21b0c112c31ea197d1cb00493d1dddc78b90c5745e"

	strings:
		$s1 = "return $qwery45234dws($b);" fullword ascii

	condition:
		( uint16(0)==0x3f3c and 1 of them )
}
