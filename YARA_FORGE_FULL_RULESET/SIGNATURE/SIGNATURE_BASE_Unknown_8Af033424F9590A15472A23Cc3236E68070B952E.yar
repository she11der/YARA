rule SIGNATURE_BASE_Unknown_8Af033424F9590A15472A23Cc3236E68070B952E : FILE
{
	meta:
		description = "Detects a web shell"
		author = "Florian Roth (Nextron Systems)"
		id = "fcf467b6-f49a-52d0-a57f-9f3cf6d0b25b"
		date = "2016-09-10"
		modified = "2023-12-05"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L9540-L9555"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d7dc9a2a5e0800b5061cb2101d7cda023a6e637f1e7b14054fdb6a0b2cec6084"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3382b5eaaa9ad651ab4793e807032650667f9d64356676a16ae3e9b02740ccf3"

	strings:
		$s1 = "$check = $_SERVER['DOCUMENT_ROOT']" fullword ascii
		$s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
		$s3 = "fwrite($fp,base64_decode('" ascii

	condition:
		( uint16(0)==0x6324 and filesize <6KB and ( all of ($s*))) or ( all of them )
}
