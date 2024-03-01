import "pe"

rule SIGNATURE_BASE_Ncrack
{
	meta:
		description = "This signature detects the Ncrack brute force tool"
		author = "Florian Roth (Nextron Systems)"
		id = "c1c56ee9-7f76-5440-b0e0-86e372c53340"
		date = "2014-01-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L141-L154"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a42bfaefb873a10821bcc06db109d8ab20daa8c8ac0b6cfb245d2ee339f318bb"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "NcrackOutputTable only supports adding up to 4096 to a cell via"

	condition:
		1 of them
}
