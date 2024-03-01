import "pe"

rule SIGNATURE_BASE_Windowscredentialeditor
{
	meta:
		description = "Windows Credential Editor"
		author = "Florian Roth"
		id = "1542c6e4-36b2-5272-85d0-43226869b43e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L20-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "531a0bdc893d89b1c14deee11df95b430051cef07744a15b5d606e1c5378db97"
		score = 90
		quality = 85
		tags = ""
		threat_level = 10

	strings:
		$a = "extract the TGT session key"
		$b = "Windows Credentials Editor"

	condition:
		all of them
}
