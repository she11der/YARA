rule SIGNATURE_BASE_Suspicious_Script_Running_From_HTTP
{
	meta:
		description = "Detects a suspicious "
		author = "Florian Roth (Nextron Systems)"
		id = "9ba84e9c-a32b-5f66-8d50-75344599cafc"
		date = "2017-08-20"
		modified = "2023-12-05"
		reference = "https://www.hybrid-analysis.com/sample/a112274e109c5819d54aa8de89b0e707b243f4929a83e77439e3ff01ed218a35?environmentId=100"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_suspicious_strings.yar#L48-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "49ead238b9153886ddbcfe37939628fd848283373e2807797d0849559ebecf6c"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "cmd /C script:http://" ascii nocase
		$s2 = "cmd /C script:https://" ascii nocase
		$s3 = "cmd.exe /C script:http://" ascii nocase
		$s4 = "cmd.exe /C script:https://" ascii nocase

	condition:
		1 of them
}
