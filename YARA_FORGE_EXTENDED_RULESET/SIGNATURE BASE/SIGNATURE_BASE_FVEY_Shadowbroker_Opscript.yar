rule SIGNATURE_BASE_FVEY_Shadowbroker_Opscript
{
	meta:
		description = "Auto-generated rule - file opscript.se"
		author = "Florian Roth (Nextron Systems)"
		id = "d00752a3-d5c2-53a7-9a83-ad31cfb534af"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L134-L147"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "23dd6d537a8639bd84ede141cca577dc91328bd293f96f865c7dedd9ef693ee3"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "275c91531a9ac5a240336714093b6aa146b8d7463cb2780cfeeceaea4c789682"

	strings:
		$s1 = "ls -l /tmp) | bdes -k 0x4790cae5ec154ccc|" ascii

	condition:
		1 of them
}
