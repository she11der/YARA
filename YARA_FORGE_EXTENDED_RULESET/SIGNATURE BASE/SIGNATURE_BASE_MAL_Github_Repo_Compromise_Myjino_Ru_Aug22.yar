rule SIGNATURE_BASE_MAL_Github_Repo_Compromise_Myjino_Ru_Aug22
{
	meta:
		description = "Detects URL mentioned in report on compromised Github repositories in August 2022"
		author = "Florian Roth (Nextron Systems)"
		id = "1eaabad5-d0de-5d17-a5fa-3c638354843d"
		date = "2022-08-03"
		modified = "2023-12-05"
		reference = "https://twitter.com/stephenlacy/status/1554697077430505473"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_github_repo_compromise_myjino_ru.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5cbe6ee46a68d89b1e772762e29baa907458235cd014f20a0d0932e95c046f19"
		score = 90
		quality = 85
		tags = ""

	strings:
		$x1 = "curl http://ovz1.j19544519.pr46m.vps.myjino.ru" ascii wide
		$x2 = "http__.Post(\"http://ovz1.j19544519.pr46m.vps.myjino.ru" ascii wide

	condition:
		1 of them
}
