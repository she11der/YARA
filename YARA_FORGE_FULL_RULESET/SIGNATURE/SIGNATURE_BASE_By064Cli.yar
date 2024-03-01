rule SIGNATURE_BASE_By064Cli
{
	meta:
		description = "Webshells Auto-generated - file by064cli.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9ea88f0c-9275-5567-a4d9-0545de8044d1"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8517-L8529"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "10e0dff366968b770ae929505d2a9885"
		logic_hash = "51efd5c510efc6657ae175af47b09437ae70eb0237d88ffdf3cdae365d0ec7be"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "packet dropped,redirecting"
		$s9 = "input the password(the default one is 'by')"

	condition:
		all of them
}
