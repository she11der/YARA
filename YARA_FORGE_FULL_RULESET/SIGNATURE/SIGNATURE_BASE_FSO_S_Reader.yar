rule SIGNATURE_BASE_FSO_S_Reader
{
	meta:
		description = "Webshells Auto-generated - file reader.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "d596f7f4-5b0d-5f17-94d3-2582ec041eb1"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7378-L7389"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"
		logic_hash = "89a948f8da66173965884cd525615c8eeb91cf98a4984c05be7472034bb72f76"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "mailto:mailbomb@hotmail."

	condition:
		all of them
}
