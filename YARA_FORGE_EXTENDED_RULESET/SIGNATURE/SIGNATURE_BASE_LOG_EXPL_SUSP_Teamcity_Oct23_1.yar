rule SIGNATURE_BASE_LOG_EXPL_SUSP_Teamcity_Oct23_1
{
	meta:
		description = "Detects log entries that could indicate a successful exploitation of TeamCity servers"
		author = "Florian Roth"
		id = "4845b40a-cf77-53ae-b2fa-d1ed861153f2"
		date = "2023-10-02"
		modified = "2023-12-05"
		reference = "https://attackerkb.com/topics/1XEEEkGHzt/cve-2023-42793/rapid7-analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/expl_teamcity_2023_42793.yar#L20-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "a2f0abffb9c72e6b32875310e5af7365b6cab4e6c4f6188daa3085b57c38ed0e"
		score = 70
		quality = 85
		tags = ""

	strings:
		$a1 = "tbrains.buildServer.ACTIVITIES"
		$s1 = "External process is launched by user user with id"
		$s2 = ". Command line: cmd.exe \"/c whoami"

	condition:
		all of them
}
